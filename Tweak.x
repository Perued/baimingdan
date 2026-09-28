#import <Foundation/Foundation.h>

// ==========================================
// 1. 获取沙盒路径
// ==========================================
static NSString *getConfigPlistPath() {
    NSString *docDir = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    return [docDir stringByAppendingPathComponent:@"InterceptConfig.plist"];
}

static NSString *getLogFilePath() {
    NSString *docDir = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    return [docDir stringByAppendingPathComponent:@"InterceptLog.txt"];
}

// ==========================================
// 2. 通用日志写入模块
// ==========================================
static void writeLog(NSString *msg) {
    NSString *logPath = getLogFilePath();
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
    NSString *timeStr = [formatter stringFromDate:[NSDate date]];
    NSString *logMsg = [NSString stringWithFormat:@"[%@] %@\n", timeStr, msg];
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:logPath]) {
        [logMsg writeToFile:logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } else {
        NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:logPath];
        [handle seekToEndOfFile];
        [handle writeData:[logMsg dataUsingEncoding:NSUTF8StringEncoding]];
        [handle closeFile];
    }
}

// ==========================================
// 3. 核心拦截器 (URL 域名匹配)
// ==========================================
static NSURL* processURL(NSURL *originalURL) {
    if (!originalURL) return originalURL;
    NSString *urlStr = originalURL.absoluteString;
    if (urlStr.length == 0) return originalURL;
    
    NSDictionary *config = [NSDictionary dictionaryWithContentsOfFile:getConfigPlistPath()];
    if (config) {
        NSArray *domains = config[@"TargetDomains"];
        if ([domains isKindOfClass:[NSArray class]]) {
            for (NSString *domain in domains) {
                if (domain.length > 0 && [urlStr containsString:domain]) {
                    if ([config[@"EnableLogging"] boolValue]) {
                        writeLog([NSString stringWithFormat:@"🛡️ 域名拦截: %@", urlStr]);
                    }
                    return [NSURL URLWithString:@"http://127.0.0.1/blackhole_dynamic_plist"];
                }
            }
        }
    }
    return originalURL;
}

// ==========================================
// 4. 插件初始化：自动生成包含“动态篡改字典”的 Plist
// ==========================================
%ctor {
    NSString *plistPath = getConfigPlistPath();
    if (![[NSFileManager defaultManager] fileExistsAtPath:plistPath]) {
        NSDictionary *defaultConfig = @{
            @"EnableLogging": @(YES),
            @"AutoRecordNewParams": @(YES), // 开启自动收录新字段
            @"TargetDomains": @[
                @"ddk_transporterinfo_updateCoordinator_v1"
            ],
            @"ResponseReplacements": @{     // 动态篡改字典 (Key: 字段名, Value: 你的自定义值)
                @"ForbiddenJailBroken": @"0",
                @"forceUnRoot": @"0",
                @"DDJailBrokenMonterAppName": @"com.fake.app.nothing"
            }
        };
        [defaultConfig writeToFile:plistPath atomically:YES];
    }
}

// ==========================================
// 5. 网络请求 Hook 层 (基于 URL 拦截)
// ==========================================
%hook NSMutableURLRequest
- (void)setURL:(NSURL *)URL {
    NSURL *safeURL = processURL(URL);
    %orig(safeURL);
}
%end

%hook NSURLRequest
+ (instancetype)requestWithURL:(NSURL *)URL {
    NSURL *safeURL = processURL(URL);
    return %orig(safeURL);
}
- (instancetype)initWithURL:(NSURL *)URL {
    NSURL *safeURL = processURL(URL);
    return %orig(safeURL);
}
- (instancetype)initWithURL:(NSURL *)URL cachePolicy:(NSURLRequestCachePolicy)cachePolicy timeoutInterval:(NSTimeInterval)timeoutInterval {
    NSURL *safeURL = processURL(URL);
    return %orig(safeURL, cachePolicy, timeoutInterval);
}
%end

// ==========================================
// 6. JSON 数据篡改与后台自动收录层
// ==========================================
%hook NSJSONSerialization

+ (id)JSONObjectWithData:(NSData *)data options:(NSJSONReadingOptions)opt error:(NSError **)error {
    id result = %orig(data, opt, error);

    // 基础类型校验
    if (![result isKindOfClass:[NSDictionary class]]) return result;
    NSDictionary *dict = (NSDictionary *)result;
    
    NSDictionary *content = dict[@"content"];
    if (![content isKindOfClass:[NSDictionary class]]) return result;

    NSArray *resultArray = content[@"result"];
    if (![resultArray isKindOfClass:[NSArray class]]) return result;

    NSDictionary *config = [NSDictionary dictionaryWithContentsOfFile:getConfigPlistPath()];
    NSDictionary *replacements = config[@"ResponseReplacements"];
    BOOL enableLogging = [config[@"EnableLogging"] boolValue];
    BOOL autoRecord = [config[@"AutoRecordNewParams"] boolValue];
    
    // 【功能 A】：异步后台收录未知的下发字段
    if (autoRecord) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
            NSMutableDictionary *liveConfig = [[NSDictionary dictionaryWithContentsOfFile:getConfigPlistPath()] mutableCopy];
            if (liveConfig) {
                NSMutableDictionary *liveReplacements = [liveConfig[@"ResponseReplacements"] mutableCopy] ?: [NSMutableDictionary dictionary];
                BOOL needSave = NO;
                
                for (NSDictionary *item in resultArray) {
                    if ([item isKindOfClass:[NSDictionary class]]) {
                        NSString *pName = item[@"paramName"];
                        NSString *pVal = item[@"paramValue"];
                        // 如果 Plist 里还没有这个字段，就把官方的默认值先收录进去
                        if (pName && pVal && !liveReplacements[pName]) {
                            liveReplacements[pName] = pVal;
                            needSave = YES;
                        }
                    }
                }
                // 只有发现新字段时才执行耗时的磁盘写入
                if (needSave) {
                    liveConfig[@"ResponseReplacements"] = liveReplacements;
                    [liveConfig writeToFile:getConfigPlistPath() atomically:YES];
                    if (enableLogging) {
                        writeLog(@"📝 Plist更新: 已将服务端新下发的字段收录进字典，可前往修改。");
                    }
                }
            }
        });
    }

    // 【功能 B】：实时动态篡改已配置的字段
    if ([replacements isKindOfClass:[NSDictionary class]] && replacements.count > 0) {
        @try {
            BOOL isModified = NO;
            NSMutableArray *logDetails = [NSMutableArray array];
            
            NSMutableDictionary *mutDict = [dict mutableCopy];
            NSMutableDictionary *mutContent = [content mutableCopy];
            NSMutableArray *mutArray = [NSMutableArray array];

            for (NSDictionary *item in resultArray) {
                if ([item isKindOfClass:[NSDictionary class]]) {
                    NSString *name = item[@"paramName"];
                    
                    // 如果当前字段在你 Plist 的替换名单里
                    if (name && replacements[name]) {
                        NSMutableDictionary *mutItem = [item mutableCopy];
                        NSString *originalVal = [NSString stringWithFormat:@"%@", mutItem[@"paramValue"]];
                        NSString *targetVal = [NSString stringWithFormat:@"%@", replacements[name]];
                        
                        // 只有当官方下发的值和你的目标值不一样时，才进行篡改
                        if (![originalVal isEqualToString:targetVal]) {
                            mutItem[@"paramValue"] = targetVal;
                            isModified = YES;
                            [logDetails addObject:[NSString stringWithFormat:@"%@ (%@ -> %@)", name, originalVal, targetVal]];
                        }
                        [mutArray addObject:mutItem];
                    } else {
                        [mutArray addObject:item];
                    }
                } else {
                    [mutArray addObject:item];
                }
            }

            // 如果发生了篡改，将修改后的数据返回给 App
            if (isModified) {
                mutContent[@"result"] = mutArray;
                mutDict[@"content"] = mutContent;
                if (enableLogging) {
                    writeLog([NSString stringWithFormat:@"✅ JSON篡改成功: %@", [logDetails componentsJoinedByString:@", "]]);
                }
                return mutDict;
            }

        } @catch (NSException *exception) {
            if (enableLogging) {
                writeLog([NSString stringWithFormat:@"❌ JSON篡改异常: %@", exception.reason]);
            }
            return result;
        }
    }

    return result;
}

%end
