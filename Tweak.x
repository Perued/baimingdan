// Tweak.xm — WeChat 8.0.74 检测 / 风控 / 上报 / 下发 全拦截 + 拦截日志
//
// 分析基础: 对 8.0.74 二进制的静态分析
//   - 59万 selector / 5.4万类,方法表逐类解析验证 (ASLR slide 0xFFFFF00000000 已校正)
//   - JailBreakHelper: 17 instance + 9 class methods,全部确认
//   - ClientCheckMgr: 17 instance methods,全部确认
//   - VpnListener: 方法表无法静态解析,改用 %ctor 运行时枚举中和
//
// 日志: 沙盒 Documents/WCNorisk_intercept.log
//   每一行: [时间] [类别] 类名 方法名 关键数据
//   类别: DETECT=检测 verdict/采集被中和, UPLOAD=上报被拦截(含上报数据),
//         DOWNLINK=服务端下发被丢弃(含下发数据)
//   单文件超 8MB 自动轮转 (.log.1 备份)
//
// 设计原则 (业务不断):
//   1. 只动检测 verdict / 采集 / 上报 / 下发,不动业务逻辑
//   2. 上报在源头掐断 (检测类内部),不动通用 KV/上报管道,避免误伤业务埋点
//   3. 返回值语义按方法名推断,注释中标注置信度
//   4. 设备指纹 (deviceId/wechatUUID) 与登录强相关,不动;Beacon 通用统计不动

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <stdarg.h>
#import <strings.h>

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

// 安全地取对象描述,超长截断,绝不抛异常
static NSString *wc_safeDesc(id obj) {
    if (!obj) return @"nil";
    @try {
        NSString *d = [obj description];
        if (!d || ![d isKindOfClass:[NSString class]])
            return [NSString stringWithFormat:@"<%@: %p>", [obj class], obj];
        if (d.length > 3000)
            d = [[d substringToIndex:3000] stringByAppendingString:@"...(truncated)"];
        // 日志单行化
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
    // 拷贝到堆上,避免 block 捕获栈上 va_list 相关对象
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
            // 轮转: 超 8MB 备份一次
            @try {
                NSDictionary *attr = [fm attributesOfItemAtPath:path error:nil];
                unsigned long long size = [attr fileSize];
                if (size > 8 * 1024 * 1024) {
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


#pragma mark - 1. JailBreakHelper:越狱检测
// 方法表来源: 二进制 __objc_data 解析 (17 instance + 9 class methods)
%hook JailBreakHelper

// --- verdict: 全部报"干净" ---
+ (BOOL)JailBroken {
    wc_log(@"DETECT", @"JailBreakHelper +JailBroken 被调用 -> 返回 NO");
    return NO;
}
- (BOOL)IsJailBreak {
    wc_log(@"DETECT", @"JailBreakHelper -IsJailBreak 被调用 -> 返回 NO");
    return NO;
}
- (BOOL)HasInstallJailbreakPlugin:(id)arg1 {
    wc_log(@"DETECT", @"JailBreakHelper -HasInstallJailbreakPlugin: 被调用 arg=%@ -> 返回 NO",
           wc_safeDesc(arg1));
    return NO;
}

// --- 路径来源: 掐断 (本地默认路径 + 服务端下发都拿不到) ---
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
- (id)m_checkPaths {
    return nil;
}
- (void)setM_checkPaths:(id)arg1 {
    // 下发拦截:服务端推送的检查路径
    wc_log(@"DOWNLINK", @"JailBreakHelper -setM_checkPaths: 丢弃服务端下发的检查路径: %@",
           wc_safeDesc(arg1));
}
+ (void)loadSetting {
    wc_log(@"DOWNLINK", @"JailBreakHelper +loadSetting 被调用 -> 跳过(含服务端设置包)");
}

// --- 节流与落盘: 冻结 ---
- (BOOL)isOverADay { return NO; }   // 永不触发"重新检查",低频,不记日志
- (void)save { }                    // 不落盘检查状态
- (void)onPackageDownloadFinish:(id)arg1 package:(id)arg2 {
    // 下发拦截:服务端越狱检查路径包
    wc_log(@"DOWNLINK", @"JailBreakHelper -onPackageDownloadFinish:package: 丢弃服务端下发的路径包 arg1=%@ package=%@",
           wc_safeDesc(arg1), wc_safeDesc(arg2));
}
- (void)onPackageListUpdated:(id)arg1 {
    wc_log(@"DOWNLINK", @"JailBreakHelper -onPackageListUpdated: 丢弃 arg=%@",
           wc_safeDesc(arg1));
}

%end


#pragma mark - 2. ClientCheckMgr:客户端完整性检查
// 触发点 onAuthOK 本体不动 (只做服务注册),掐的是它调的所有检查与上报
%hook ClientCheckMgr

// --- 检测 verdict ---
// checkConsistency: "是否一致" YES=干净 (置信度:中; 若原方法为 void,返回值被忽略,无影响)
- (BOOL)checkConsistency:(id)arg1 {
    wc_log(@"DETECT", @"ClientCheckMgr -checkConsistency: 被调用 arg=%@ -> 返回 YES(干净)",
           wc_safeDesc(arg1));
    return YES;
}
// checkHook: / checkHookWithSeq: "是否发现hook" NO=干净
// (语义类比 IsJailBreak: YES=发现问题; 置信度:中; void 亦无影响)
- (BOOL)checkHook:(id)arg1 {
    wc_log(@"DETECT", @"ClientCheckMgr -checkHook: 被调用 arg=%@ -> 返回 NO(干净)",
           wc_safeDesc(arg1));
    return NO;
}
- (BOOL)checkHookWithSeq:(id)arg1 {
    wc_log(@"DETECT", @"ClientCheckMgr -checkHookWithSeq: 被调用 arg=%@ -> 返回 NO(干净)",
           wc_safeDesc(arg1));
    return NO;
}

// --- 采集器: 返回空 ---
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
    // 下发拦截:服务端下发的检查数据
    wc_log(@"DOWNLINK", @"ClientCheckMgr -setClientCheckData: 丢弃服务端下发的检查数据: %@",
           wc_safeDesc(arg1));
}

// --- 上报: 全部静默 (reportclientcheck CGI + KV 上报的源头),记录上报数据 ---
- (void)reportFileConsistency:(id)arg1 fileName:(id)arg2 offset:(id)arg3 bufferSize:(id)arg4 seq:(id)arg5 {
    wc_log(@"UPLOAD", @"ClientCheckMgr -reportFileConsistency:... 拦截文件一致性上报 arg1=%@ fileName=%@ offset=%@ bufferSize=%@ seq=%@",
           wc_safeDesc(arg1), wc_safeDesc(arg2), wc_safeDesc(arg3),
           wc_safeDesc(arg4), wc_safeDesc(arg5));
}
- (void)reportAppList:(id)arg1 {
    // 不上报已安装应用列表,记录试图上报的数据
    wc_log(@"UPLOAD", @"ClientCheckMgr -reportAppList: 拦截应用列表上报 data=%@",
           wc_safeDesc(arg1));
}

// --- 采集回调: 不注册 ---
- (void)addImage:(id)arg1 {
    wc_log(@"DETECT", @"ClientCheckMgr -addImage: 忽略 image=%@", wc_safeDesc(arg1));
}
- (void)registerAddImageCallBack {
    wc_log(@"DETECT", @"ClientCheckMgr -registerAddImageCallBack 被调用 -> 不注册 "
           @"(_dyld_register_func_for_add_image 永不生效)");
}

// --- 下发: 服务端 sysmsg 检查任务直接丢弃,记录下发内容 ---
// (clientcheck / ClientCheckConsistency / ClientCheckHook / ClientCheckGetAppList 节点)
- (void)OnGetNewXmlMsg:(id)arg1 Type:(id)arg2 MsgWrap:(id)arg3 {
    wc_log(@"DOWNLINK", @"ClientCheckMgr -OnGetNewXmlMsg:Type:MsgWrap: 丢弃服务端下发的检查任务 "
           @"arg1=%@ type=%@ msg=%@",
           wc_safeDesc(arg1), wc_safeDesc(arg2), wc_msgWrapDetail(arg3));
}

%end


#pragma mark - 3. VpnListener:运行时中和
// VpnListener 方法表无法静态解析 (类结构异常),改用运行时枚举:
// 只处理类名含 "vpn" 的类 (排除 TVHttpProxy 等播放器代理类),
// 只中和"状态查询"语义的方法 (is/status/connect/check/used),
// BOOL 返回 -> NO, void -> 空实现,其他返回类型不动。

static BOOL wc_vpnReturnNO(id self, SEL _cmd) {
    wc_log(@"DETECT", @"VPN 运行时hook: %@ -> 返回 NO",
           NSStringFromSelector(_cmd));
    return NO;
}
static void wc_vpnNoop(id self, SEL _cmd) {
    wc_log(@"DETECT", @"VPN 运行时hook: %@ -> 空实现",
           NSStringFromSelector(_cmd));
}

static void wc_neutralizeVpnClass(Class cls) {
    if (!cls) return;
    for (int meta = 0; meta < 2; meta++) {
        Class c = meta ? object_getClass(cls) : cls;
        unsigned int count = 0;
        Method *methods = class_copyMethodList(c, &count);
        for (unsigned int i = 0; i < count; i++) {
            SEL sel = method_getName(methods[i]);
            NSString *name = [[NSStringFromSelector(sel) lowercaseString] copy];
            if ([name rangeOfString:@"vpn"].location == NSNotFound) continue;
            BOOL looksLikeCheck =
                [name rangeOfString:@"is"].location != NSNotFound ||
                [name rangeOfString:@"status"].location != NSNotFound ||
                [name rangeOfString:@"connect"].location != NSNotFound ||
                [name rangeOfString:@"check"].location != NSNotFound ||
                [name rangeOfString:@"used"].location != NSNotFound;
            if (!looksLikeCheck) continue;
            const char *enc = method_getTypeEncoding(methods[i]);
            if (!enc) continue;
            if (enc[0] == 'B' || enc[0] == 'c') {
                // BOOL 查询 -> 一律"未使用 VPN"
                class_replaceMethod(c, sel, (IMP)wc_vpnReturnNO, enc);
                wc_log(@"DETECT", @"VPN 运行时hook已安装: %@(%@) -> NO",
                       NSStringFromClass(cls), NSStringFromSelector(sel));
            } else if (enc[0] == 'v') {
                class_replaceMethod(c, sel, (IMP)wc_vpnNoop, enc);
                wc_log(@"DETECT", @"VPN 运行时hook已安装: %@(%@) -> noop",
                       NSStringFromClass(cls), NSStringFromSelector(sel));
            }
            // 其他返回类型 (对象等): 不动,避免破坏
        }
        free(methods);
    }
}

%ctor {
    @autoreleasepool {
        wc_log(@"DETECT", @"WCNorisk 加载,开始安装 hooks");
        unsigned int classCount = objc_getClassList(NULL, 0);
        Class *classes = (Class *)malloc(sizeof(Class) * classCount);
        classCount = objc_getClassList(classes, classCount);
        for (unsigned int i = 0; i < classCount; i++) {
            const char *cname = class_getName(classes[i]);
            if (cname && strcasestr(cname, "vpn") != NULL
                && strcasestr(cname, "proxy") == NULL) {
                wc_neutralizeVpnClass(classes[i]);
            }
        }
        free(classes);
        wc_log(@"DETECT", @"WCNorisk hooks 安装完成");
    }
}
