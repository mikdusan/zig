### freebsd-syscall branch goals

To create an API layer `sys` that reasonably matches approximates `c`.
This layer does not require linking to libc. Instead it makes syscalls.

On a case-by-case bases, some functions may need to be specialized in
a number of ways, like calling a specific syscall version, or using
a more functional syscall, eg:

    - implementing `open` with `openat`
    - implementing `creat` with `openat`
    - implementing `lstat` with `fstatat`

### feature testing

1. Syscall layer is implemented as reify'd enum `sys.SYS` which only
   contains those syscalls known to be available on the targeted OS version.
   `@hasField()` is used heavily when implementing functions.

2. Testing whether or not a function or type is implemented is done
   with "feature" testing. Each function/type may be always implemented,
   or conditionally implemented. When using conditionals, `missing_feature`
   is a global comptime singleton marking the decl as a missing feature.

   eg: `sys.hasFeature(.openat)` or `c.hasFeature(.openat)` is used
   for writing tests that are skipped when key features are missing.

3. The os-layer is responsible for avaibility and versioning details for
   both `sys` and `c`. In this manner, other namepsaces do not need to hardcode
   knowledge of feature availability.

   In status-quo zig, "timerfd" is a feature currently implemented only
   for linux. Let's see what happens for freebsd:

    1. test guard hard-codes for linux
    2. test guard will later need to be modified when we add freebsd support
    3. using `timerfd_create` successfully compiles
    4. using `timerfd_create` successfully links
    5. using `timerfd_create` fails runtime with bad syscall
    6. on linux, no guards for timerfd_create availability (2.6.22 kernel)

   With feature testing:

    1. test guards could be unified and use `hasFeature`
    2. use without guards is a compile error; eg:
        ```
        error: type 'type' not a function
        try missing_feature();
            ^~~~~~~~~~~~~~~
        ```

   Similar issues of maintenance for `c` layer can also benefit when the
   mere availability of a function/type can be determined without the need
   to hardcode os/version at many sites.

### errno

While syscalls do not need to explicitly have or deal with a global or
thread-local `errno`, diverging from this API would have consequences on
code that can use both `c` or `sys`. It will also defeat the purpose of
this layer. Therefore, we also implement ways to set and access `errno`
consistent with the `c` layer.

### tests

Tests written to be agnostic to `sys` and `c` namespaces. When building
with libc, both `sys` and `c` tests will run, otherwise only the`sys` run.

### changes to the status-quo `c` namespace approach

1. Prefer to use `foo_t` naming convention for types. Even if the equivalent
C API is not suffixed with `_t` we add the suffix. eg:

    - use `sigaction_t` instead of `sigaction` as in C, or `Sigaction` as in Zig
    - use `sigval_t` instead of `sigval`

2. In some cases, re-implement groups of C functions as members of a `_t` type.

For working with signal sets, we have `sigset_t` and implement the operations
as member functions. The available of C functions across unixes and versions is
very inconsistent. By taking this approach we offer the same rich interface to
both `sys` and `c`.

3. Prefer to use `snake_case` when implementing functions in `_t` types. This:

```
sigset_t.assign_from()
sigset_t.is_empty()
sigset_t.is_set()
sigset_t.and_with()
sigset_t.or_with()
```

vs.

```
sigset_t.assignFrom()
sigset_t.isEmpty()
sigset_t.isSet()
sigset_t.andWith()
sigset_t.orWith()
```
