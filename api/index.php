<?php
$yourHost = 'https://e8.gs/'; // 替换为您的域名
$seed = '这是一个种子'; // 设置种子
$dataDir = './seed-' . md5($seed); // 种子目录
$whiteListFile = $dataDir . '/white.list'; // 白名单文件路径
$blackListFile = $dataDir . '/ban.list'; // 黑名单文件路径
$allowedExtensions = ['css', 'js', 'img', 'image', 'images', 'cache', 'admin', 'm']; // 保留的后缀
$allowedChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-';

// 启用或禁用白名单和黑名单功能
$whiteListEnabled = false; // 设置为 true 启用白名单功能
$blackListEnabled = false;  // 设置为 true 启用黑名单功能

// 设置时区
date_default_timezone_set('PRC');

// 生成随机令牌
function token($length) {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; 
    $password = ""; 
    for ($i = 0; $i < $length; $i++) { 
        $password .= $chars[mt_rand(0, strlen($chars) - 1)]; 
    } 
    return $password; 
}

// 获取客户端IP地址
function getIP($type = 0, $adv = true) {
    $type = $type ? 1 : 0;
    static $ip = NULL;
    if ($ip !== NULL) return $ip[$type];
    if ($adv) {
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $arr = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $pos = array_search('unknown', $arr);
            if (false !== $pos) unset($arr[$pos]);
            $ip = trim($arr[0]);
        } elseif (isset($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (isset($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
    } elseif (isset($_SERVER['REMOTE_ADDR'])) {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    // IP地址合法验证
    $long = sprintf("%u", ip2long($ip));
    $ip   = $long ? array($ip, $long) : array('0.0.0.0', 0);
    return $ip[$type];
}

// 检查URL是否在黑名单中
function isBlacklisted($url) {
    global $blackListFile, $blackListEnabled;
    if (!$blackListEnabled) {
        return false;
    }
    if (!file_exists($blackListFile)) {
        // 如果黑名单文件不存在且功能启用，创建文件
        file_put_contents($blackListFile, '', LOCK_EX);
    }
    $blacklist = file($blackListFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($blacklist as $blacklisted) {
        if (stripos($url, $blacklisted) !== false) {
            return true;
        }
    }
    return false;
}

// 检查URL是否在白名单中
function isWhitelisted($url) {
    global $whiteListFile, $whiteListEnabled;
    if (!$whiteListEnabled) {
        return true;
    }
    if (!file_exists($whiteListFile)) {
        return false;
    }
    $whitelist = file($whiteListFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $parsedUrl = parse_url($url);
    $host = isset($parsedUrl['host']) ? $parsedUrl['host'] : '';
    return in_array($host, $whitelist);
}

// 生成随机短代码
function generateShortCode() {
    global $allowedChars, $allowedExtensions;
    do {
        $shortCode = substr(md5(uniqid(mt_rand(), true)), 1, 7);
        $valid = true;
        // 检查是否有不允许的字符
        foreach (str_split($shortCode) as $char) {
            if (strpos($allowedChars, $char) === false) {
                $valid = false;
                break;
            }
        }
        // 检查是否为保留后缀
        if (in_array($shortCode, $allowedExtensions)) {
            $valid = false;
        }
    } while (!$valid);
    return $shortCode;
}

// 保存短链接数据
function saveLinkData($data, $id) {
    global $dataDir;
    $file = $dataDir . '/data-' . $id . '.json';

    // 编码数据为JSON字符串并加上换行符
    $jsonString = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";

    // 追加数据到文件
    file_put_contents($file, $jsonString, FILE_APPEND | LOCK_EX);
}

// 检查有效期
function isExpired($expiry) {
    if (empty($expiry)) {
        return false;
    }
    $expiryDate = DateTime::createFromFormat('Y-m-d H:i:s', $expiry);
    $currentDate = new DateTime();
    return $expiryDate < $currentDate;
}

// 检查短链接的有效性和生成
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 创建种子目录如果不存在
    if (!file_exists($dataDir)) {
        mkdir($dataDir, 0755, true);
    }

    $originalUrl = isset($_POST['url']) ? $_POST['url'] : '';
    $customCode = isset($_POST['custom_code']) ? $_POST['custom_code'] : '';
    $expiry = isset($_POST['expiry']) ? $_POST['expiry'] : '';

    if ($originalUrl == '') {
        echo json_encode(['code' => 400, 'msg' => 'URL 不能为空']);
        exit;
    } elseif (substr($originalUrl, 0, 4) !== 'http') {
        $originalUrl = (substr($originalUrl, 0, 1) !== ':' && substr($originalUrl, 0, 2) == '//') 
                        ? 'http:' . $originalUrl 
                        : 'http://' . $originalUrl;
    }

    if (isBlacklisted($originalUrl)) {
        echo json_encode(['code' => 403, 'msg' => 'URL 在黑名单中']);
        exit;
    }

    if (!isWhitelisted($originalUrl)) {
        echo json_encode(['code' => 403, 'msg' => 'URL 不在白名单中']);
        exit;
    }

    if (!empty($customCode)) {
        // 验证自定义短链接代码
        if (preg_match('/^[a-zA-Z0-9_\-]+$/', $customCode) && !in_array($customCode, $allowedExtensions)) {
            $file = $dataDir . '/data-' . substr($customCode, 0, 2) . '.json';
            $exists = false;
            if (file_exists($file)) {
                $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                foreach ($lines as $line) {
                    $link = json_decode($line, true);
                    if ($link['short'] === $customCode) {
                        $exists = true;
                        break;
                    }
                }
            }
            if ($exists) {
                echo json_encode(['code' => 409, 'msg' => '自定义短链接已存在']);
                exit;
            }
            $shortCode = $customCode;
        } else {
            echo json_encode(['code' => 400, 'msg' => '无效的自定义后缀']);
            exit;
        }
    } else {
        $shortCode = generateShortCode();
    }

    $data = [
        'short' => $shortCode,
        'url' => $originalUrl,
        'time' => date('Y-m-d H:i:s', time()),
        'method' => $_SERVER['REQUEST_METHOD'],
        'ip' => getIP(),
        'expiry' => $expiry,
    ];
    saveLinkData($data, substr($shortCode, 0, 2));
    echo json_encode(['code' => 200, 'msg' => '成功', 'url' => $yourHost . $shortCode]);
    exit;
}

// 短链接重定向
if (isset($_GET['code'])) {
    $code = $_GET['code'];
    $file = $dataDir . '/data-' . substr($code, 0, 2) . '.json';

    if (!file_exists($file)) {
        echo json_encode(['code' => 404, 'msg' => '短链接未找到']);
        exit;
    }

    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

    foreach ($lines as $line) {
        $link = json_decode($line, true);
        if ($link['short'] === $code) {
            if (isset($link['expiry']) && isExpired($link['expiry'])) {
                echo json_encode(['code' => 410, 'msg' => '短链接已过期']);
                exit;
            }
            header("Location: {$link['url']}", true, 302);
            exit;
        }
    }

    echo json_encode(['code' => 404, 'msg' => '短链接未找到']);
    exit;
}
?>
<!DOCTYPE html><html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>短链接生成器</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            padding: 20px;
            text-align: center;
        }
        #message {
            display: none;
            padding: 10px;
            margin-top: 10px;
            border-radius: 5px;
            color: white;
            background-color: green;
            font-size: 16px;
        }
        form {
            margin: 0 auto;
            max-width: 400px;
            text-align: left;
        }
        label {
            display: block;
            margin-bottom: 10px;
        }
        input[type="text"], input[type="url"], input[type="submit"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        input[type="submit"] {
            background-color: #4CAF50;
            color: white;
            border: none;
            cursor: pointer;
        }
        input[type="submit"]:hover {
            background-color: #45a049;
        }
        footer {
            margin-top: 20px;
            font-size: 14px;
            color: #666;
        }
    </style>
</head>
<body>
    <h1>短链接生成器</h1>
    <form id="linkForm">
        <label for="url">原始URL：</label>
        <input type="url" id="url" name="url" required>
        
        <label for="custom_code">自定义后缀（可选）：</label>
        <input type="text" id="custom_code" name="custom_code">
        
        <label for="expiry">有效期（可选，格式如 2024-12-31 23:59:59）：</label>
        <input type="text" id="expiry" name="expiry">
        
        <input type="submit" value="生成短链接">
    </form>
    <div id="message"></div>
    
    <footer>
        &copy; 2024 e8.gs. 版权所有.
    </footer>

    <script>
        document.getElementById('linkForm').addEventListener('submit', function(event) {
            event.preventDefault();
            
            var formData = new FormData(this);
            
            fetch('index.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                var messageBox = document.getElementById('message');
                
                if (data.code === 200) {
                    // 成功，显示短链接并复制到剪贴板
                    messageBox.textContent = '生成成功: ' + data.url;
                    messageBox.style.display = 'block';

                    navigator.clipboard.writeText(data.url).then(function() {
                        // 在绿色小框中显示提示信息
                        messageBox.textContent += ' 已复制到剪贴板';
                    });
                } else {
                    // 失败，显示错误信息
                    messageBox.textContent = data.msg;
                    messageBox.style.display = 'block';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                var messageBox = document.getElementById('message');
                messageBox.textContent = '生成短链接时发生错误';
                messageBox.style.display = 'block';
            });
        });
    </script>
</body>
</html>
