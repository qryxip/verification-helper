import abc
import collections
import json
import pathlib
import shutil
import subprocess
from logging import getLogger
from subprocess import PIPE
from typing import *

from onlinejudge_verify.config import get_config
from onlinejudge_verify.languages import special_comments
from onlinejudge_verify.languages.models import Language, LanguageEnvironment

logger = getLogger(__name__)
_cargo_checked_workspaces: Set[pathlib.Path] = set()
_source_file_sets_by_package_manifest_path: Dict[pathlib.Path, FrozenSet[FrozenSet[pathlib.Path]]] = {}


class _ListDependenciesBackend(object):
    @abc.abstractmethod
    def list_dependencies(self, metadata: Dict[str, Any], package: Dict[str, Any], target: Dict[str, Any], other_metadata: List[Dict[str, Any]]) -> Dict[pathlib.Path, List[pathlib.Path]]:
        raise NotImplementedError


class _RelatedRsFiles(object):
    paths: Dict[pathlib.Path, FrozenSet[pathlib.Path]]
    _cargo_checked_workspaces: Set[pathlib.Path]

    def __init__(self):
        self.paths = {}
        self._visited = set()

    def collect(self, all_metadata: Iterable[Dict[str, Any]]) -> None:
        for metadata in all_metadata:
            if pathlib.Path(metadata['workspace_root']) in self._visited:
                continue
            self._visited.add(pathlib.Path(metadata['workspace_root']))

            subprocess.run(
                ['cargo', 'check', '--manifest-path', str(pathlib.Path(metadata['workspace_root'], 'Cargo.toml')), '--workspace', '--all-targets'],
                cwd=metadata['workspace_root'],
                check=True,
            )

            for ws_member in (p for p in metadata['packages'] if p['id'] in metadata['workspace_members']):
                for target in ws_member['targets']:
                    src_path = pathlib.Path(target['src_path'])

                    d_file_paths = sorted(
                        pathlib.Path(metadata['target_directory'], 'debug', 'deps').glob(f'{target["name"].replace("-", "_")}-*.d'),
                        key=lambda p: p.stat().st_mtime_ns,
                        reverse=True,
                    )
                    for d_file_path in d_file_paths:
                        # Like this:
                        #
                        # ```
                        # /home/ryo/src/github.com/rust-lang-ja/ac-library-rs/target/debug/deps/ac_library_rs-a044142420f688ff.rmeta: src/lib.rs src/convolution.rs src/dsu.rs src/fenwicktree.rs src/lazysegtree.rs src/math.rs src/maxflow.rs src/mincostflow.rs src/modint.rs src/scc.rs src/segtree.rs src/string.rs src/twosat.rs src/internal_bit.rs src/internal_math.rs src/internal_queue.rs src/internal_scc.rs src/internal_type_traits.rs
                        #
                        # /home/ryo/src/github.com/rust-lang-ja/ac-library-rs/target/debug/deps/ac_library_rs-a044142420f688ff.d: src/lib.rs src/convolution.rs src/dsu.rs src/fenwicktree.rs src/lazysegtree.rs src/math.rs src/maxflow.rs src/mincostflow.rs src/modint.rs src/scc.rs src/segtree.rs src/string.rs src/twosat.rs src/internal_bit.rs src/internal_math.rs src/internal_queue.rs src/internal_scc.rs src/internal_type_traits.rs
                        #
                        # src/lib.rs:
                        # src/convolution.rs:
                        # src/dsu.rs:
                        # src/fenwicktree.rs:
                        # src/lazysegtree.rs:
                        # src/math.rs:
                        # src/maxflow.rs:
                        # src/mincostflow.rs:
                        # src/modint.rs:
                        # src/scc.rs:
                        # src/segtree.rs:
                        # src/string.rs:
                        # src/twosat.rs:
                        # src/internal_bit.rs:
                        # src/internal_math.rs:
                        # src/internal_queue.rs:
                        # src/internal_scc.rs:
                        # src/internal_type_traits.rs:
                        # ```
                        with open(d_file_path) as d_file:
                            d = d_file.read()
                        related_rs_files = None
                        for line in d.splitlines():
                            words = line.split(':')
                            if len(words) == 2 and pathlib.Path(words[0]) == d_file_path:
                                paths = [pathlib.Path(metadata['workspace_root'], s) for s in words[1].split() if not pathlib.Path(s).is_absolute()]
                                if paths[:1] == [src_path]:
                                    related_rs_files = frozenset(paths)
                                    break
                        if related_rs_files is not None:
                            self.paths[src_path] = related_rs_files
                            break
                    else:
                        logger.warning(f'no `.d` file for `{target["name"]}`')


class _NoBackend(_ListDependenciesBackend):
    _related_rs_files: _RelatedRsFiles

    def __init__(self):
        self._related_rs_files = _RelatedRsFiles()

    def list_dependencies(self, metadata: Dict[str, Any], package: Dict[str, Any], target: Dict[str, Any], other_metadata: List[Dict[str, Any]]) -> Dict[pathlib.Path, List[pathlib.Path]]:
        return _list_dependencies_by_crate(metadata, package, target, other_metadata, cargo_udeps_toolchain=None, related_rs_files=self._related_rs_files)


class _CargoUdeps(_ListDependenciesBackend):
    _toolchain: str = 'nightly'
    _related_rs_files: _RelatedRsFiles

    def __init__(self, *, toolchain: Optional[str]):
        if toolchain is not None:
            self._toolchain = toolchain
        self._related_rs_files = _RelatedRsFiles()

    def list_dependencies(self, metadata: Dict[str, Any], package: Dict[str, Any], target: Dict[str, Any], other_metadata: List[Dict[str, Any]]) -> Dict[pathlib.Path, List[pathlib.Path]]:
        return _list_dependencies_by_crate(metadata, package, target, other_metadata, cargo_udeps_toolchain=self._toolchain, related_rs_files=self._related_rs_files)


def _list_dependencies_by_crate(metadata: Dict[str, Any], package: Dict[str, Any], target: Dict[str, Any], other_metadata: List[Dict[str, Any]], cargo_udeps_toolchain: Optional[str], related_rs_files: _RelatedRsFiles) -> Dict[pathlib.Path, List[pathlib.Path]]:
    src_path = pathlib.Path(target['src_path'])

    related_rs_files.collect([metadata, *other_metadata])

    ret = collections.defaultdict(set, {src_path: {src_path}})
    if src_path in related_rs_files.paths:
        rs_paths = related_rs_files.paths[src_path]
        for rs_path in rs_paths:
            ret[rs_path] |= rs_paths

    packages_by_id = {package['id']: package for package in metadata['packages']}
    normal_build_node_deps = {
        normal_build_node_dep['name']: normal_build_node_dep['pkg']
        for node in metadata['resolve']['nodes']
        if node['id'] == package['id']
        for normal_build_node_dep in node['deps']
        if not packages_by_id[normal_build_node_dep['pkg']]['source'] and any(
            not dep_kind['kind'] or dep_kind['kind'] == 'build'
            for dep_kind in normal_build_node_dep['dep_kinds']
        )
    } # yapf: disable

    if not _is_lib_or_proc_macro(target) and any(map(_is_lib_or_proc_macro, package['targets'])):
        normal_build_node_deps[package['name']] = package['id']

    unused_packages = set()
    if cargo_udeps_toolchain is not None:
        renames = {dependency['rename'] for dependency in package['dependencies'] if dependency['rename']}
        if not shutil.which('cargo-udeps'):
            raise RuntimeError('`cargo-udeps` not in $PATH')
        unused_deps = json.loads(subprocess.run(
            ['rustup', 'run', cargo_udeps_toolchain, 'cargo', 'udeps', '--output', 'json', '--manifest-path', package['manifest_path'], *_target_option(target)],
            check=False,
            stdout=PIPE,
        ).stdout.decode())['unused_deps'].values()
        for unused_dep in unused_deps:
            if unused_dep['manifest_path'] == package['manifest_path']:
                for name_in_toml in [*unused_dep['normal'], *unused_dep['development'], *unused_dep['build']]:
                    if name_in_toml in renames:
                        unused_packages.add(normal_build_node_deps[name_in_toml])
                    else:
                        for package_id in normal_build_node_deps.values():
                            if packages_by_id[package_id]['name'] == name_in_toml:
                                unused_packages.add(package_id)

    for dep_package_id in normal_build_node_deps.values():
        if dep_package_id not in unused_packages:
            dep_package = packages_by_id[dep_package_id]
            for dep_target in dep_package['targets']:
                dep_src_path = pathlib.Path(dep_target['src_path'])
                if _is_lib_or_proc_macro(dep_target):
                    ret[src_path] |= related_rs_files.paths[dep_src_path]
                    break
    return {k: sorted(v) for k, v in ret.items()}


class _Results(object):
    list_dependencies: DefaultDict[pathlib.Path, List[pathlib.Path]]
    is_verification_file: Set[pathlib.Path]
    get_compile_command: Dict[pathlib.Path, List[str]]
    get_execute_command: Dict[pathlib.Path, List[str]]

    def __init__(self):
        self.list_dependencies = collections.defaultdict(list)
        self.is_verification_file = set()
        self.get_compile_command = {}
        self.get_execute_command = {}


class RustLanguageEnvironment(LanguageEnvironment):
    _results: _Results

    def __init__(self, results: _Results):
        self._results = results

    def compile(self, path: pathlib.Path, *, basedir: pathlib.Path, tempdir: pathlib.Path) -> None:
        subprocess.run(
            self._results.get_compile_command[basedir / path],
            cwd=path.parent,
            check=True,
        )

    def get_execute_command(self, path: pathlib.Path, *, basedir: pathlib.Path, tempdir: pathlib.Path) -> List[str]:
        return self._results.get_execute_command[basedir / path]


class RustLanguage(Language):
    _backend_or_results: Union[_ListDependenciesBackend, _Results]

    def __init__(self, *, config: Optional[Dict[str, Any]] = None):
        if config is None:
            config = get_config().get('languages', {}).get('rust', {})
        if 'list_dependencies_backend' in config:
            list_dependencies_backend = config['list_dependencies_backend']
            if not isinstance(list_dependencies_backend, dict):
                raise RuntimeError('`languages.rust.list_dependencies_backend` must be `dict`')
            if 'kind' not in list_dependencies_backend:
                raise RuntimeError('missing `languages.rust.list_dependencies_backend.kind`')
            list_dependencies_backend_kind = list_dependencies_backend['kind']
            if not isinstance(list_dependencies_backend_kind, str):
                raise RuntimeError('`languages.rust.list_dependencies_backend.kind` must be `str`')
            if list_dependencies_backend_kind == 'none':
                list_dependencies_backend = _NoBackend()
            elif list_dependencies_backend_kind == 'cargo-udeps':
                if 'toolchain' not in list_dependencies_backend:
                    toolchain = None
                elif isinstance(list_dependencies_backend['toolchain'], str):
                    toolchain = list_dependencies_backend['toolchain']
                else:
                    raise RuntimeError('`languages.rust.list_dependencies_backend.toolchain` must be `str`')
                list_dependencies_backend = _CargoUdeps(toolchain=toolchain)
            else:
                raise RuntimeError("expected 'none' or 'cargo-udeps' for `languages.rust.list_dependencies_backend.kind`")
        else:
            list_dependencies_backend = _NoBackend()

        self._backend_or_results = list_dependencies_backend

    def results(self, basedir: pathlib.Path) -> _Results:
        if isinstance(self._backend_or_results, _ListDependenciesBackend):
            list_dependencies_backend = self._backend_or_results
            results = _Results()

            all_metadata: List[Dict[str, Any]] = []

            for manifest_path in sorted(basedir.rglob('Cargo.toml')):
                metadata = json.loads(subprocess.run(
                    ['cargo', 'metadata', '--format-version', '1', '--manifest-path', str(manifest_path)],
                    stdout=PIPE,
                    cwd=manifest_path.parent,
                    check=True,
                ).stdout.decode())

                if not any(m['workspace_root'] == metadata['workspace_root'] for m in all_metadata):
                    all_metadata.append(metadata)

            for metadata in all_metadata:
                other_metadata = [m for m in all_metadata if m['workspace_root'] != metadata['workspace_root']]

                for ws_member in filter(lambda p: p['id'] in metadata['workspace_members'], metadata['packages']):
                    for target in ws_member['targets']:
                        src_path = pathlib.Path(target['src_path'])

                        if _is_bin_or_example_bin(target) and 'PROBLEM' in special_comments.list_special_comments(src_path):
                            results.is_verification_file.add(src_path)
                            results.get_compile_command[src_path] = ['cargo', 'build', '--release', *_target_option(target)]
                            results.get_execute_command[src_path] = [str(pathlib.Path(metadata['target_directory'], 'release', *([] if _is_bin(target) else ['examples']), target['name']))]

                        for rs_from, rs_to in list_dependencies_backend.list_dependencies(metadata, ws_member, target, other_metadata).items():
                            results.list_dependencies[rs_from].extend(rs_to)

            self._backend_or_results = results

        return self._backend_or_results

    def list_dependencies(self, path: pathlib.Path, *, basedir: pathlib.Path) -> List[pathlib.Path]:
        path = basedir / path
        results = self.results(basedir).list_dependencies
        if path not in results:
            logger.warning(f'`{path}` was not recognized. is this a generated file?')
        return results[path] or [path]

    def bundle(self, path: pathlib.Path, *, basedir: pathlib.Path, options: Dict[str, Any]) -> bytes:
        raise NotImplementedError

    def is_verification_file(self, path: pathlib.Path, *, basedir: pathlib.Path) -> bool:
        path = basedir / path
        results = self.results(basedir).is_verification_file
        return path in results

    def list_environments(self, path: pathlib.Path, *, basedir: pathlib.Path) -> Sequence[RustLanguageEnvironment]:
        return [RustLanguageEnvironment(self.results(basedir))]


def _is_lib_or_proc_macro(target: Dict[str, Any]) -> bool:
    return target['kind'] in [['lib'], ['proc-macro']]


def _is_bin(target: Dict[str, Any]) -> bool:
    return target['kind'] == ['bin']


def _is_bin_or_example_bin(target: Dict[str, Any]) -> bool:
    return _is_bin(target) or target['kind'] == ['example'] and target['crate_types'] == ['bin']


def _target_option(target: Dict[str, Any]) -> List[str]:
    if target['kind'] == ['bin']:
        return ['--bin', target['name']]
    if target['kind'] == ['example']:
        return ['--example', target['name']]
    if target['kind'] == ['test']:
        return ['--test', target['name']]
    if target['kind'] == ['bench']:
        return ['--bench', target['name']]
    return ['--lib']
