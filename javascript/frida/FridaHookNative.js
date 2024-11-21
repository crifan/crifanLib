/*
	File: FridaHookNative.js
	Function: crifan's Frida hook common native related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/javascript/frida/FridaHookNative.js
	Updated: 20241121
*/

// Frida hook common native functions
class FridaHookNative {
  constructor() {
    console.log("FridaHookNative constructor")
  }

  static hookNative_dlopen(){
    // void *dlopen(const char *filename, int flags);
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
      onEnter: function (args) {
        var filename = FridaUtil.ptrToCStr(args[0])
        var flags = args[1]
        console.log("dlopen: [+] filename=" + filename + ", flags=" + flags)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_open(){
    // int open(const char *pathname, int flags, mode_t mode);
    Interceptor.attach(Module.findExportByName(null, "open"), {
      onEnter: function (args) {
        var path = FridaUtil.ptrToCStr(args[0])
        var oflags = args[1]
        // console.log("open: [+] path=" + path + ", oflags=" + oflags)
        this._path = path
        this._oflags = oflags
      },
      onLeave: function (retFd) {
        // console.log("\t open retFd=" + retFd)
        console.log("open: [+] path=" + this._path + ", oflags=" + this._oflags + " -> retFd=" + retFd)
      }
    })
  }

  static hookNative_read(){
    // ssize_t read(int fd, void buf[.count], size_t count)
    Interceptor.attach(Module.findExportByName(null, "read"), {
      onEnter: function (args) {
        var fd = args[0]
        var buf = args[1]
        var count = args[2]
        console.log("read: fd=" + fd + ", buf=" + buf + ", count=" + count)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_write(){
    // ssize_t write(int fildes, const void *buf, size_t nbyte)
    Interceptor.attach(Module.findExportByName(null, "write"), {
      onEnter: function (args) {
        var fildes = args[0]
        var buf = args[1]
        var nbyte = args[2]
        console.log("write: fildes=" + fildes + ", buf=" + buf + ", nbyte=" + nbyte)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_close(){
    // int close(int fd)
    Interceptor.attach(Module.findExportByName(null, "close"), {
      onEnter: function (args) {
        var fd = args[0]
        console.log("close: fd=" + fd)
      },
      onLeave: function (retval) {
      }
    })
  }

  static hookNative_remove(){
    // int remove(const char *path)
    Interceptor.attach(Module.findExportByName(null, "remove"), {
      onEnter: function (args) {
        var path = FridaUtil.ptrToCStr(args[0])
        console.log("remove: path=" + path)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_fopen(){
    // FILE *fopen(const char *filename, const char *mode);
    // FILE *fopen(const char *restrict pathname, const char *restrict mode);
  
    Interceptor.attach(Module.findExportByName(null, "fopen"), {
      onEnter: function (args) {
        var pathname = FridaUtil.ptrToCStr(args[0])
        var mode = FridaUtil.ptrToCStr(args[1])
        // console.log("fopen: pathname=" + pathname + ", mode=" + mode)
        this._pathname = pathname
        this._mode = mode
      },
      onLeave: function (retFile) {
        // console.log("fopen: retFile=" + retFile)
        console.log("fopen: pathname=" + this._pathname + ", mode=" + this._mode + " -> retFile=" + retFile)
      }
    })
  
    // var FuncPtr_fopen = Module.findExportByName(null, "fopen")
    // console.log("FuncPtr_fopen=" + FuncPtr_fopen)
    // if (null != FuncPtr_fopen) {
    //   var func_fopen = new NativeFunction(FuncPtr_fopen, 'pointer', ['pointer', 'pointer'])
    //   console.log("func_fopen=" + func_fopen)
    //   Interceptor.replace(func_fopen,
    //     new NativeCallback(function (filename, mode) {
    //       // console.log("filename=" + filename + ", mode=" + mode)
    //       var filenameStr = filename.readUtf8String()
    //       // console.log("filenameStr=" + filenameStr)
    //       var modeStr = mode.readUtf8String()
    //       // console.log("modeStr=" + modeStr)
    //       var retFile = func_fopen(filename, mode)
    //       // console.log("retFile=" + retFile)
    //       console.log("filename=" + filename + "=" + filenameStr + ", mode=" + mode + "=" + modeStr + "-> retFile" + retFile)
    //       return retFile
    //     },
    //     'pointer',
    //     ['pointer', 'pointer'])
    //   )
    // }
  
  }

  static hookNative_flock(){
    // int flock(int fd, int operation);
    Interceptor.attach(Module.findExportByName(null, "flock"), {
      onEnter: function (args) {
        var fd = args[0]
        var operation = args[1]
        console.log("flock: fd=" + fd + ", operation=" + operation)
      },
      onLeave: function (retval) {
      }
    });
  }

  static hookNative_strcpy(){
    const KnownStrLis = [
      "",
      "/",
      "zh",
      "CN",
      "zh_CN",
      "Hans",
      "zh_Hans",
      "zh_Hans_CN",
      "en",
      "US",
      "en_US",
    ]
  
    // char *strcpy(char *restrict dst, const char *restrict src);
    Interceptor.attach(Module.findExportByName(null, "strcpy"), {
      onEnter: function (args) {
        var dst = FridaUtil.ptrToCStr(args[0])
        var src = FridaUtil.ptrToCStr(args[1])
        if (!KnownStrLis.includes(src)) {
          console.log("strcpy: dst=" + dst + ", src=" + src)
        }
      },
      onLeave: function (args) {
      }
    })
  }
  
  static hookNative_strncpy(){
    // char *strncpy(char *dest, const char *src, size_t count);
    Interceptor.attach(Module.findExportByName(null, "strncpy"), {
      onEnter: function (args) {
        var dest = FridaUtil.ptrToCStr(args[0])
        var src = FridaUtil.ptrToCStr(args[1])
        var count = args[2]
        console.log("strncpy: dest=" + dest + ", src=" + src + ", count=" + count)
      },
      onLeave: function (args) {
      }
    })
  }
  
  static hookNative_strcat(){
    // char *strcat(char *restrict dst, const char *restrict src);
    Interceptor.attach(Module.findExportByName(null, "strcat"), {
      onEnter: function (args) {
        var dst = FridaUtil.ptrToCStr(args[0])
        var src = FridaUtil.ptrToCStr(args[1])
        console.log("strcat: dst=" + dst + ", src=" + src)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_execlp(){
    // int execlp(const char *path, const char *arg0, ..., NULL);
    Interceptor.attach(Module.findExportByName(null, "execlp"), {
      onEnter: function (args) {
        var path = FridaUtil.ptrToCStr(args[0])
        var arg0 = FridaUtil.ptrToCStr(args[1])
        var arg1 = FridaUtil.ptrToCStr(args[2])
        console.log("execlp: path=" + path + ", arg0=" + arg0 + ", arg1=" + arg1)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_execv(){
    // int execv(const char *pathname, char *const argv[]);
    Interceptor.attach(Module.findExportByName(null, "execv"), {
      onEnter: function (args) {
        var pathname = FridaUtil.ptrToCStr(args[0])
        var argv = args[1]
        console.log("execv: pathname=" + pathname + ", argv=" + argv)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_pthread_create(){
    // int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void*), void *arg);
    Interceptor.attach(Module.findExportByName(null, "pthread_create"), {
      onEnter: function (args) {
        var thread = args[0]
        var attr = args[1]
        var start_routine = args[2]
        var arg = args[3]
        console.log("pthread_create: thread=" + thread + ", attr=" + attr + ", start_routine=" + start_routine + ", arg=" + arg)
      },
      onLeave: function (retNewPid) {
        console.log("\t pthread_create retNewPid= " + retNewPid)
      }
    })
  }

  static hookNative_clone(){
    // int clone(int (*fn)(void *_Nullable), void *stack, int flags, void *_Nullable arg, ...  /* pid_t *_Nullable parent_tid, void *_Nullable tls, pid_t *_Nullable child_tid */ );
    Interceptor.attach(Module.findExportByName(null, "clone"), {
      onEnter: function (args) {
        var fn = args[0]
        var stack = args[1]
        var flags = args[2]
        var arg = args[3]
        console.log("clone: fn=" + fn + ", stack=" + stack + ", flags=" + flags + ", arg=" + arg)
      },
      onLeave: function (retval) {
      }
    })
  }

  static hookNative_fork(){
    // pid_t fork(void);
    Interceptor.attach(Module.findExportByName(null, "fork"), {
      onEnter: function (args) {
        console.log("fork called")
      },
      onLeave: function (retval) {
        console.log("\t fork retval= " + retval)
      }
    })
  }

  static hookNative_posix_spawn(){
    // int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]);
    Interceptor.attach(Module.findExportByName(null, "posix_spawn"), {
      onEnter: function (args) {
        var pid = args[0]
        var path = FridaUtil.ptrToCStr(args[1])
        var file_actions = args[2]
        var attrp = args[3]
        var argv = args[4]
        var envp = args[5]
        console.log("posix_spawn: pid=" + pid + ", path=" + path + ", file_actions=" + file_actions + ", attrp=" + attrp + ", argv=" + argv + ", envp=" + envp)
      },
      onLeave: function (retval) {
      }
    })
  }

  static hookNative_posix_spawnp(){
    // int posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]);
    Interceptor.attach(Module.findExportByName(null, "posix_spawnp"), {
      onEnter: function (args) {
        var pid = args[0]
        var file = FridaUtil.ptrToCStr(args[1])
        var file_actions = args[2]
        var attrp = args[3]
        var argv = args[4]
        var envp = args[5]
        console.log("posix_spawnp: pid=" + pid + ", file=" + file + ", file_actions=" + file_actions + ", attrp=" + attrp + ", argv=" + argv + ", envp=" + envp)
      },
      onLeave: function (retval) {
      }
    })
  }

  static hookNative_sigaction(){
    // int sigaction(int signum, const struct sigaction *_Nullable restrict act, struct sigaction *_Nullable restrict oldact);
    Interceptor.attach(Module.findExportByName(null, "sigaction"), {
      onEnter: function (args) {
        var signum = args[0]
        var actP = args[1]
        var oldactP = args[2]
        console.log("sigaction: signum=" + signum + ", actP=" + actP + ", oldactP=" + oldactP)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_killpg(){
    // int killpg(int pgrp, int sig)
    Interceptor.attach(Module.findExportByName(null, "killpg"), {
      onEnter: function (args) {
        var pgrp = args[0]
        var sig = args[1]
        console.log("killpg: pgrp=" + pgrp + ", sig=" + sig)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_pread(){
    // ssize_t pread(int fildes, void *buf, size_t nbyte, off_t offset)
    Interceptor.attach(Module.findExportByName(null, "pread"), {
      onEnter: function (args) {
        var fildes = args[0]
        var buf = args[1]
        var nbyte = args[2]
        var offset = args[3]
        console.log("pread: fildes=" + fildes + ", buf=" + buf + ", nbyte=" + nbyte + ", offset=" + offset)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_pwrite(){
    // ssize_t pwrite(int fildes, const void *buf, size_t nbyte, off_t offset)
    Interceptor.attach(Module.findExportByName(null, "pwrite"), {
      onEnter: function (args) {
        var fildes = args[0]
        var buf = args[1]
        var nbyte = args[2]
        var offset = args[3]
        console.log("pwrite: fildes=" + fildes + ", buf=" + buf + ", nbyte=" + nbyte + ", offset=" + offset)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_pipe(){
    // int pipe(int pipefd[2])
    Interceptor.attach(Module.findExportByName(null, "pipe"), {
      onEnter: function (args) {
        var pipefdArray = args[0]
        console.log("pipe: pipefdArray=" + pipefdArray)
      },
      onLeave: function (retval) {
      }
    })
  }

  static hookNative_getpid(){
    // pid_t getpid(void)
    Interceptor.attach(Module.findExportByName(null, "getpid"), {
      onEnter: function (args) {
        // console.log("getpid called")
      },
      onLeave: function (retPid) {
        console.log("\t getpid retPid=" + retPid)
      }
    })
  }

  static hookNative_getppid(){
    // pid_t getppid(void)
    Interceptor.attach(Module.findExportByName(null, "getppid"), {
      onEnter: function (args) {
        console.log("getppid called")
      },
      onLeave: function (retval) {
        console.log("\t getppid retval=" + retval)
      }
    })
  }

  static hookNative_setsid(){
    // pid_t setsid(void)
    Interceptor.attach(Module.findExportByName(null, "setsid"), {
      onEnter: function (args) {
        console.log("setsid called")
      },
      onLeave: function (retval) {
        console.log("\t setsid retval=" + retval)
      }
    })
  }

}