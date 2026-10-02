// Tweak.xm — WeChat 检测 / 风控 / 上报 / 下发 全拦截 + 拦截日志
//
// v3 (2026-10-02):
//   - 去掉 %ctor 里的 VPN 运行时扫描: 启动期零额外工作, 不再 patch Apple 私有类
//     (AWDVPNSession), 看门狗风险最低。VPN hook 待启动稳定后按需加回。
//   - 参数类型安全: 不确定的参数不再盲声明为 id, 而是按方法真实 type
//     encoding 逐个解析 (对象才发 description, 整数按数字打印)。
//     原因: 8.0.75 签名可能与 8.0.74 不同; 对整数发 description 会
//     EXC_BAD_ACCESS, 且 @try/@catch 拦不住 Mach 异常。
//   - %ctor 记录当前 App 版本, 便于排查版本漂移 (8.0.74 方法表 vs 运行版本)。
// v3.2 (2026-10-02):
//   - loadSetting 纠正: 反汇编 8.0.74 的 +loadSetting 证实为纯本地配置文件
//     加载 (getJailbreakPath -> FileExist -> dataWithContentsOfFile ->
//     decodeObjectOfClass:fromData:, 无网络请求), 日志类别由 [DOWNLINK]
//     改为 [CONFIG]。服务端下发走 onPackageDownloadFinish:package:。
// v3.3 (2026-10-02):
//   - HEALTH 自检输出已拦截的完整方法清单 (按类分组), 不只报缺失。
// v3.1 (2026-10-02):
//   - 新增启动后 hook 健康自检: 延迟 3 秒在后台队列执行, 逐个验证 27 个
//     hook 目标方法是否存在 (存在 => %hook 已挂上), 结果写入 [HEALTH] 日志。
//
// 分析基础: 8.0.74 二进制静态分析 (JailBreakHelper / ClientCheckMgr 方法表逐类验证)
// 日志: 沙盒 Documents/WCNorisk_intercept.log (8MB 轮转)
// 类别: DETECT=检测 verdict/采集被中和, UPLOAD=上报被拦截(含数据),
//       DOWNLINK=服务端下发被丢弃(含数据), CONFIG=本地检测配置加载被跳过,
//       HEALTH=hook 健康自检
//
// 设计原则 (业务不断):
//   1. 只动检测 verdict / 采集 / 上报 / 下发,不动业务逻辑
//   2. 上报在源头掐断,不动通用 KV/上报管道
//   3. 返回值语义按方法名推断,注释标注置信度
//   4. 设备指纹不动; Beacon 通用统计不动

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <stdarg.h>
#import <string.h>

#pragma mark - 日志工具

static NSString *wc_logPath(void) {
    static NSString *path = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        path = [[dirs firstObject] stringByAppendingPathComponent:@"WCNorisk_intercept.log"];
    });
    return path;
}

static dispatch_queue_t wc_logQueue(void) {
    static dispatch_queue_t q = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        q = dispatch_queue_create("com.user.wcnorisk.log", DISPATCH_QUEUE_SERIAL);
    });
    return q;
}

// 安全地取对象描述,超长截断,绝不抛 NSException
// 注意: 只对确认是对象的值调用; Mach 异常 (@try 拦不住) 靠调用方保证类型
static NSString *wc_safeDesc(id obj) {
    if (!obj) return @"nil";
    @try {
        NSString *d = [obj description];
        if (!d || ![d isKindOfClass:[NSString class]])
            return [NSString stringWithFormat:@"<%@: %p>", [obj class], obj];
        if (d.length > 3000)
            d = [[d substringToIndex:3000] stringByAppendingString:@"...(truncated)"];
        d = [d stringByReplacingOccurrencesOfString:@"\n" withString:@"\\n"];
        d = [d stringByReplacingOccurrencesOfString:@"\r" withString:@"\\r"];
        return d;
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"<desc failed: %@ %p>", [obj class], obj];
    }
}

static void wc_log(NSString *category, NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    msg = [msg copy];
    dispatch_async(wc_logQueue(), ^{
        @autoreleasepool {
            static NSDateFormatter *fmt = nil;
            if (!fmt) {
                fmt = [[NSDateFormatter alloc] init];
                fmt.dateFormat = @"yyyy-MM-dd HH:mm:ss";
            }
            NSString *line = [NSString stringWithFormat:@"[%@] [%@] %@\n",
                              [fmt stringFromDate:[NSDate date]], category, msg];
            NSString *path = wc_logPath();
            NSFileManager *fm = [NSFileManager defaultManager];
            @try {
                NSDictionary *attr = [fm attributesOfItemAtPath:path error:nil];
                if ([attr fileSize] > 8 * 1024 * 1024) {
                    NSString *bak = [path stringByAppendingString:@".1"];
                    [fm removeItemAtPath:bak error:nil];
                    [fm moveItemAtPath:path toPath:bak error:nil];
                }
            } @catch (NSException *e) {}
            @try {
                if (![fm fileExistsAtPath:path])
                    [@"" writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
                NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
                [fh seekToEndOfFile];
                [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
                [fh closeFile];
            } @catch (NSException *e) {}
        }
    });
}

// 尝试从 MsgWrap 里抠出下发的具体内容
static NSString *wc_msgWrapDetail(id wrap) {
    if (!wrap) return @"nil";
    NSMutableString *s = [NSMutableString stringWithFormat:@"<%@: %p>",
                          [wrap class], wrap];
    NSArray *keys = @[@"message", @"m_nsContent", @"content",
                      @"m_uiMessageType", @"m_nsFromUsr", @"m_nsToUsr"];
    for (NSString *k in keys) {
        @try {
            id v = [wrap valueForKey:k];
            if (v) [s appendFormat:@" | %@=%@", k, wc_safeDesc(v)];
        } @catch (NSException *e) {}
    }
    [s appendFormat:@" | desc=%@", wc_safeDesc(wrap)];
    return s;
}

#pragma mark - 参数类型安全格式化

// 跳过 type encoding 修饰符 (r/n/N/o/O/R/V)
static const char *wc_skipQual(const char *p) {
    while (*p=='r'||*p=='n'||*p=='N'||*p=='o'||*p=='O'||*p=='R'||*p=='V') p++;
    return p;
}

// 跳过一个完整类型 (含 @"Class" / struct / array / union / 指针)
static const char *wc_skipType(const char *p) {
    p = wc_skipQual(p);
    if (*p == '^') return wc_skipType(p + 1);
    if (*p == '@') {
        if (p[1] == '"') { p += 2; while (*p && *p != '"') p++; if (*p) p++; }
        else p++;
        return p;
    }
    if (*p == '{' || *p == '(' || *p == '[') {
        char open = *p, close = (open == '{') ? '}' : (open == '(') ? ')' : ']';
        int depth = 0;
        do { if (*p == open) depth++; else if (*p == close) depth--; p++; } while (*p && depth > 0);
        return p;
    }
    if (*p) p++;
    return p;
}

// 按方法真实 type encoding 安全格式化参数。
// raw[i] = 第 i 个参数的 8 字节原始槽位 (ARM64 上对象与整数都在通用寄存器)。
// 只有编码为 @/# 的才当对象发 description; 整数族按数字打印;
// float/double 在浮点寄存器, 通用寄存器值不可靠, 只标 hex 不解读。
static NSString *wc_formatArgs(id self, SEL sel, unsigned long long *raw, int maxArgs) {
    @try {
        Class c = object_getClass(self); // 实例->类, 类->元类, 统一处理
        Method m = class_getInstanceMethod(c, sel);
        if (!m) return @"<方法未找到,encoding 不可用>";
        const char *enc = method_getTypeEncoding(m);
        if (!enc || !*enc) return @"<无 encoding>";
        NSMutableString *s = [NSMutableString stringWithFormat:@"enc=%s", enc];
        const char *p = wc_skipType(enc); // 返回值
        p = wc_skipType(p);               // self
        while (*p >= '0' && *p <= '9') p++;
        p = wc_skipType(p);               // _cmd
        while (*p >= '0' && *p <= '9') p++;
        int idx = 0;
        while (*p && idx < maxArgs) {
            char t = *wc_skipQual(p);
            unsigned long long v = raw[idx];
            if (t == '@' || t == '#') {
                [s appendFormat:@" | a%d=%@", idx, wc_safeDesc((__bridge id)(void *)v)];
            } else if (t=='c'||t=='i'||t=='s'||t=='l'||t=='q') {
                [s appendFormat:@" | a%d=%lld (0x%llx)", idx, (long long)v, v];
            } else if (t=='C'||t=='I'||t=='S'||t=='L'||t=='Q'||t=='B') {
                [s appendFormat:@" | a%d=%llu (0x%llx)", idx, v, v];
            } else if (t=='f' || t=='d') {
                [s appendFormat:@" | a%d=<float/double,通用寄存器值不可靠>", idx];
            } else if (t=='*' || t==':') {
                [s appendFormat:@" | a%d=0x%llx", idx, v];
            } else if (t=='{' || t=='(' || t=='[' || t=='^') {
                [s appendFormat:@" | a%d=<复合类型 0x%llx>", idx, v];
            } else {
                [s appendFormat:@" | a%d=<未知类型 %c 0x%llx>", idx, t, v];
            }
            p = wc_skipType(p);
            while (*p >= '0' && *p <= '9') p++;
            idx++;
        }
        return s;
    } @catch (NSException *e) {
        return @"<参数格式化失败>";
    }
}

#pragma mark - 1. JailBreakHelper:越狱检测
// 方法表来源: 8.0.74 二进制 __objc_data 解析
%hook JailBreakHelper

+ (BOOL)JailBroken {
    wc_log(@"DETECT", @"JailBreakHelper +JailBroken 被调用 -> 返回 NO");
    return NO;
}
- (BOOL)IsJailBreak {
    wc_log(@"DETECT", @"JailBreakHelper -IsJailBreak 被调用 -> 返回 NO");
    return NO;
}
// 参数类型不确定 -> 走 encoding 解析, 防整数参数
- (BOOL)HasInstallJailbreakPlugin:(unsigned long long)r0 {
    unsigned long long raw[1] = {r0};
    wc_log(@"DETECT", @"JailBreakHelper -HasInstallJailbreakPlugin: 被调用 %@ -> 返回 NO",
           wc_formatArgs(self, _cmd, raw, 1));
    return NO;
}

+ (id)getJailbreakPath {
    wc_log(@"DETECT", @"JailBreakHelper +getJailbreakPath 被调用 -> 返回 nil");
    return nil;
}
+ (id)getJailbreakRootDir {
    wc_log(@"DETECT", @"JailBreakHelper +getJailbreakRootDir 被调用 -> 返回 nil");
    return nil;
}
+ (id)getIAPCheckPath {
    wc_log(@"DETECT", @"JailBreakHelper +getIAPCheckPath 被调用 -> 返回 nil");
    return nil;
}
- (id)m_checkPaths { return nil; }
- (void)setM_checkPaths:(id)arg1 {
    // 下发拦截: 服务端推送的检查路径
    wc_log(@"DOWNLINK", @"JailBreakHelper -setM_checkPaths: 丢弃服务端下发的检查路径: %@",
           wc_safeDesc(arg1));
}
+ (void)loadSetting {
    // 反汇编 8.0.74 确认: 纯本地配置文件加载, 无网络请求。
    // getJailbreakPath(沙盒路径) -> FileExist -> dataWithContentsOfFile ->
    // decodeObjectOfClass:fromData:(反序列化出检测路径配置);
    // 文件不存在则 CreateFile 建默认配置 -> encodeDataWithObject -> writeToFile 写回。
    // 服务端下发走 onPackageDownloadFinish:package: 那条 (已另行拦截)。
    // 跳过 = 检测模块拿不到检测路径 (IsJailBreak 本来也直接返回 NO, 双保险)。
    wc_log(@"CONFIG", @"JailBreakHelper +loadSetting 被调用 -> 跳过本地检测配置加载");
}

- (BOOL)isOverADay { return NO; } // 永不触发"重新检查", 低频, 不记日志
- (void)save { }                   // 不落盘检查状态
- (void)onPackageDownloadFinish:(id)arg1 package:(id)arg2 {
    // 下发拦截: 服务端越狱检查路径包
    wc_log(@"DOWNLINK", @"JailBreakHelper -onPackageDownloadFinish:package: 丢弃服务端下发的路径包 "
           @"arg1=%@ package=%@", wc_safeDesc(arg1), wc_safeDesc(arg2));
}
- (void)onPackageListUpdated:(id)arg1 {
    wc_log(@"DOWNLINK", @"JailBreakHelper -onPackageListUpdated: 丢弃 arg=%@",
           wc_safeDesc(arg1));
}

%end

#pragma mark - 2. ClientCheckMgr:客户端完整性检查
// 触发点 onAuthOK 本体不动, 掐的是它调的所有检查与上报
%hook ClientCheckMgr

// checkConsistency: "是否一致" YES=干净 (置信度:中)
- (BOOL)checkConsistency:(unsigned long long)r0 {
    unsigned long long raw[1] = {r0};
    wc_log(@"DETECT", @"ClientCheckMgr -checkConsistency: 被调用 %@ -> 返回 YES(干净)",
           wc_formatArgs(self, _cmd, raw, 1));
    return YES;
}
// checkHook:/checkHookWithSeq: "是否发现hook" NO=干净 (置信度:中)
- (BOOL)checkHook:(unsigned long long)r0 {
    unsigned long long raw[1] = {r0};
    wc_log(@"DETECT", @"ClientCheckMgr -checkHook: 被调用 %@ -> 返回 NO(干净)",
           wc_formatArgs(self, _cmd, raw, 1));
    return NO;
}
- (BOOL)checkHookWithSeq:(unsigned long long)r0 {
    unsigned long long raw[1] = {r0};
    wc_log(@"DETECT", @"ClientCheckMgr -checkHookWithSeq: 被调用 %@ -> 返回 NO(干净)",
           wc_formatArgs(self, _cmd, raw, 1));
    return NO;
}

// 采集器: 返回空
- (NSArray *)runningProcesses {
    wc_log(@"DETECT", @"ClientCheckMgr -runningProcesses 被调用 -> 返回空数组");
    return @[];
}
- (NSArray *)getImageList {
    wc_log(@"DETECT", @"ClientCheckMgr -getImageList 被调用 -> 返回空数组");
    return @[];
}
- (id)clientCheckData { return nil; }
- (void)setClientCheckData:(id)arg1 {
    // 下发拦截: 服务端下发的检查数据
    wc_log(@"DOWNLINK", @"ClientCheckMgr -setClientCheckData: 丢弃服务端下发的检查数据: %@",
           wc_safeDesc(arg1));
}

// 上报: 全部静默, 记录上报数据。offset/bufferSize/seq 疑似整数 -> 走 encoding 解析。
- (void)reportFileConsistency:(unsigned long long)r0 fileName:(unsigned long long)r1
                      offset:(unsigned long long)r2 bufferSize:(unsigned long long)r3
                         seq:(unsigned long long)r4 {
    unsigned long long raw[5] = {r0, r1, r2, r3, r4};
    wc_log(@"UPLOAD", @"ClientCheckMgr -reportFileConsistency:... 拦截文件一致性上报 %@",
           wc_formatArgs(self, _cmd, raw, 5));
}
- (void)reportAppList:(id)arg1 {
    // 不上报已安装应用列表, 记录试图上报的数据
    wc_log(@"UPLOAD", @"ClientCheckMgr -reportAppList: 拦截应用列表上报 data=%@",
           wc_safeDesc(arg1));
}

// 采集回调: 不注册
- (void)addImage:(id)arg1 {
    wc_log(@"DETECT", @"ClientCheckMgr -addImage: 忽略 image=%@", wc_safeDesc(arg1));
}
- (void)registerAddImageCallBack {
    wc_log(@"DETECT", @"ClientCheckMgr -registerAddImageCallBack 被调用 -> 不注册");
}

// 下发: 服务端 sysmsg 检查任务直接丢弃, 记录下发内容
- (void)OnGetNewXmlMsg:(id)arg1 Type:(id)arg2 MsgWrap:(id)arg3 {
    wc_log(@"DOWNLINK", @"ClientCheckMgr -OnGetNewXmlMsg:Type:MsgWrap: 丢弃服务端下发的检查任务 "
           @"arg1=%@ type=%@ msg=%@",
           wc_safeDesc(arg1), wc_safeDesc(arg2), wc_msgWrapDetail(arg3));
}

%end

#pragma mark - 4. 启动自检 (hook 健康度)
// 延迟到启动后执行, 不占启动路径。只做存在性检查:
// 方法存在 => Logos %hook 已挂上 (不存在的方法 %hook 会静默跳过)。
// 注意: 这只能证明"挂上了", 不能证明"服务端下发了检查任务"。
static void wc_healthCheck(void) {
    @autoreleasepool {
        struct { const char *cls; const char *sel; BOOL isClass; } items[] = {
            {"JailBreakHelper", "JailBroken", YES},
            {"JailBreakHelper", "IsJailBreak", NO},
            {"JailBreakHelper", "HasInstallJailbreakPlugin:", NO},
            {"JailBreakHelper", "getJailbreakPath", YES},
            {"JailBreakHelper", "getJailbreakRootDir", YES},
            {"JailBreakHelper", "getIAPCheckPath", YES},
            {"JailBreakHelper", "m_checkPaths", NO},
            {"JailBreakHelper", "setM_checkPaths:", NO},
            {"JailBreakHelper", "loadSetting", YES},
            {"JailBreakHelper", "isOverADay", NO},
            {"JailBreakHelper", "save", NO},
            {"JailBreakHelper", "onPackageDownloadFinish:package:", NO},
            {"JailBreakHelper", "onPackageListUpdated:", NO},
            {"ClientCheckMgr", "onAuthOK", NO},
            {"ClientCheckMgr", "getImageList", NO},
            {"ClientCheckMgr", "checkConsistency:", NO},
            {"ClientCheckMgr", "reportFileConsistency:fileName:offset:bufferSize:seq:", NO},
            {"ClientCheckMgr", "checkHook:", NO},
            {"ClientCheckMgr", "checkHookWithSeq:", NO},
            {"ClientCheckMgr", "reportAppList:", NO},
            {"ClientCheckMgr", "OnGetNewXmlMsg:Type:MsgWrap:", NO},
            {"ClientCheckMgr", "addImage:", NO},
            {"ClientCheckMgr", "registerAddImageCallBack", NO},
            {"ClientCheckMgr", "runningProcesses", NO},
            {"ClientCheckMgr", "clientCheckData", NO},
            {"ClientCheckMgr", "setClientCheckData:", NO},
        };
        int n = (int)(sizeof(items) / sizeof(items[0]));
        NSMutableString *okJB = [NSMutableString string];
        NSMutableString *okCC = [NSMutableString string];
        NSMutableString *miss = [NSMutableString string];
        int okCount = 0, jbCount = 0, ccCount = 0;
        for (int i = 0; i < n; i++) {
            Class cls = objc_getClass(items[i].cls);
            BOOL found = NO;
            if (cls) {
                Class c = items[i].isClass ? object_getClass(cls) : cls;
                found = (class_getInstanceMethod(c, sel_registerName(items[i].sel)) != NULL);
            }
            if (found) {
                okCount++;
                NSString *tag = [NSString stringWithFormat:@"%s%s ",
                                 items[i].isClass ? "+" : "-", items[i].sel];
                if (strcmp(items[i].cls, "JailBreakHelper") == 0) {
                    [okJB appendString:tag]; jbCount++;
                } else {
                    [okCC appendString:tag]; ccCount++;
                }
            } else {
                [miss appendFormat:@"%s[%s%s] ", items[i].cls,
                 items[i].isClass ? "+" : "-", items[i].sel];
            }
        }
        wc_log(@"HEALTH", @"自检: %d/%d 个方法存在并已 hook", okCount, n);
        wc_log(@"HEALTH", @"已拦截 JailBreakHelper(%d): %s", jbCount, [okJB UTF8String]);
        wc_log(@"HEALTH", @"已拦截 ClientCheckMgr(%d): %s", ccCount, [okCC UTF8String]);
        if (miss.length) {
            wc_log(@"HEALTH", @"缺失(未 hook): %s", [miss UTF8String]);
            wc_log(@"HEALTH", @"注意: 缺失的方法其 hook 未生效 (当前版本类/方法不存在或改名), 对应检查项无覆盖");
        } else {
            wc_log(@"HEALTH", @"缺失: 无");
        }
    }
}

#pragma mark - 5. 加载标记
// v3: %ctor 只做日志与版本记录, 不做运行时扫描/方法替换。
//     启动期零额外工作, 看门狗风险最低。
// v3.1: 增加延迟 3 秒的 hook 健康自检 (后台队列, 不占启动路径)。
%ctor {
    @autoreleasepool {
        NSString *ver = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
        NSString *build = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
        wc_log(@"DETECT", @"WCNorisk v3.3 加载完成 (方法表基于 8.0.74, 当前运行 %@ build %@)",
               ver ? ver : @"?", build ? build : @"?");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
            wc_healthCheck();
        });
    }
}
