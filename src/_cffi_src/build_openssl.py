from __future__ import annotations
import pathlib
import sys, os

src_dir = str(pathlib.Path(__file__).parent.parent)
sys.path.insert(0, src_dir)

from cffi import FFI
import platform
about: dict = {}

base_src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(base_src, "cryptography", "__about__.py")) as f:
    exec(f.read(), about)

def build_ffi_for_binding(
    module_name: str,
    module_prefix: str,
    modules: list[str],
):
    """
    Modules listed in ``modules`` should have the following attributes:

    * ``INCLUDES``: A string containing C includes.
    * ``TYPES``: A string containing C declarations for types.
    * ``FUNCTIONS``: A string containing C declarations for functions & macros.
    * ``CUSTOMIZATIONS``: A string containing arbitrary top-level C code, this
        can be used to do things like test for a define and provide an
        alternate implementation based on that.
    """
    types = []
    includes = []
    functions = []
    customizations = []
    for name in modules:
        __import__(module_prefix + name)
        module = sys.modules[module_prefix + name]

        types.append(module.TYPES)
        functions.append(module.FUNCTIONS)
        includes.append(module.INCLUDES)
        customizations.append(module.CUSTOMIZATIONS)

    verify_source = "\n".join(includes + customizations)
    return build_ffi(
        module_name,
        cdef_source="\n".join(types + functions),
        verify_source=verify_source,
    )


def build_ffi(
    module_name: str,
    cdef_source: str,
    verify_source: str,
):
    ffi = FFI()
    # Always add the CRYPTOGRAPHY_PACKAGE_VERSION to the shared object
    cdef_source += "\nstatic const char *const CRYPTOGRAPHY_PACKAGE_VERSION;"
    verify_source += '\n#define CRYPTOGRAPHY_PACKAGE_VERSION "{}"'.format(
        about["__version__"]
    )
    if platform.python_implementation() == "PyPy":
        verify_source += r"""
int Cryptography_make_openssl_module(void) {
    int result;

    Py_BEGIN_ALLOW_THREADS
    result = cffi_start_python();
    Py_END_ALLOW_THREADS

    return result;
}
"""
    ffi.cdef(cdef_source)
    ffi.set_source(
        module_name,
        verify_source,
    )
    return ffi

ffi = build_ffi_for_binding(
    module_name="_openssl",
    module_prefix="_cffi_src.openssl.",
    modules=[
        # This goes first so we can define some cryptography-wide symbols.
        "cryptography",
        "asn1",
        "bignum",
        "bio",
        "crypto",
        "dh",
        "dsa",
        "ec",
        "engine",
        "err",
        "evp",
        "nid",
        "objects",
        "opensslv",
        "pem",
        "rand",
        "rsa",
        "ssl",
        "x509",
        "x509name",
        "x509v3",
        "x509_vfy",
    ],
)