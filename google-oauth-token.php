
$usage = "Usage: $argv[0] [OPTIONS]... https://www.googleapis.com/auth/drive
    -l, --login=foo@gmail.com
        Login hint to when construction authorization URL
    
    -f, --force-refresh
    
    -i, --client-id=123.apps.googleusercontent.com
    
    -s, --client-secret=abc
    
    -v, --verbose";

$client_id = "509744952818.apps.googleusercontent.com";
$client_secret = "wFNEkla6NQci7K0xVQaJLdK3";
$dbpath = getenv("HOME") . "/.google-oauth-tokens";

//$opts = getopt($argv, "", ["scope=", "login=", "verbose", "force-refresh"]);


$login_hint = null;
$verbose = false;
$force_refresh = false;
$login_hint = null;
$cmd = array_shift($argv);

while (next_opt($opt, $val, $args)) {
    switch($opt) {
        case 'l':
        case 'login':
            $login_hint = $val;
            break;
            
        case 'f':
        case 'force-refresh':
            $force_refresh = true;
            break;
            
        case 'i':
        case 'client-id':
            $client_id = $val;
            break;
        
        case 's':
        case 'client-secret':
            $client_secret = $val;
            break;
            
        case 'v':
        case 'verbose':
            $verbose = true;
            break;
            
        default:
            usage_error("Unreconized option $opt");
    }
}

if (count($args) == 0) {
    usage_error("No scope specified");
}

$scope = implode("+", $args);

$scope = preg_replace('/\s+/', '+', $scope);

$db = open_db();
$token = get_token_from_cache($db, $scope, $login_hint);

if ($token) {
    if ($force_refresh || $token->is_expiring_soon()) {
        $success = $token->refresh();
        
        if (!$success) {
            $success = $token->authorize();
            
            if (!$success) {
                fwrite(STDERR, "Error while authorizing\n");
                exit(1);
            }
        }
        
        $token->save_to_cache($db);
        save_db($db);
    }

    echo $token->access_token . "\n";
    exit(0);
}
else {
    $token = new Token();
    $token->scope      = $scope;
    $token->login_hint = $login_hint;

    $success = $token->authorize();
    if (!$success) {
        fwrite(STDERR, "Error while authorizing\n");
        exit(1);
    }

    $token->save_to_cache($db);

    save_db($db);

    echo $token->access_token . "\n";
    exit(0);
}

class Token {
    var $access_token,
        $refresh_token,
        $expires_at,
        $login_hint,
        $scope;
    
    function is_expiring_soon() {
        if ($this->expires_at <= time() + 60*5) {
            info("Token expiring soon");
            return true;
        }
        
        return false;
    }
    
    function authorize() {
        http_server_start($server, $port);
        $redirect_uri = "http://localhost:$port/";
        $xsrf = bin2hex(openssl_random_pseudo_bytes(20));
        $auth_url = make_auth_url($this->scope, $this->login_hint, $redirect_uri, $xsrf);
        
        fwrite(STDERR, "Opening browser to $auth_url\n");
        open_browser($auth_url);

        info("Listening on port $port for token...");
        $data = http_server_recv($server);
        info("Got response from server: $data");
        
        $resp = parse_http_response($data);
        if ($resp["state"] !== $xsrf) {
            fwrite(STDERR, "WTF?! state param incorrect");
            exit(1);
        }
        
        
        if (array_key_exists("error", $resp)) {
            fwrite(STDERR, "Got error: " . $resp["error"] . "\n");
            return false;
        }
        
        $code = $resp["code"];
        $tokens = exchange_token($code, $redirect_uri);
        
        $this->access_token  = $tokens["access_token"];
        $this->refresh_token = $tokens["refresh_token"];
        $this->expires_at    = intval($tokens["expires_in"]) + time();
        
        return true;
    }
    
    function refresh() {
        global $client_id;
        global $client_secret;
        
        $url = "https://accounts.google.com/o/oauth2/token";
        $data = http_build_query(array(
            "refresh_token" => $this->refresh_token,
            "client_id" => $client_id,
            "client_secret" => $client_secret,
            "grant_type" => "refresh_token"
        ));
        
        info("Refreshing token via $url");
        
        $result_text = http_post($url, $data);
        info("Got data from server: $result_text");
        $result = json_decode($result_text, true);
        
        if (array_key_exists("error", $result)) {
            return false;
        }
        
        $this->access_token = $result["access_token"];
        $this->expires_at   = intval($result["expires_in"]) + time();
        
        return true;
    }
    
    function save_to_cache(&$db) {
        $db[$this->scope . "#" . $this->login_hint] = array(
            "access_token"  => $this->access_token,
            "refresh_token" => $this->refresh_token,
            "expires_at"    => $this->expires_at
        );
    }
}

function usage_error($msg) {
    global $usage;
    fwrite(STDERR, "$msg\n\n");
    fwrite(STDERR, "$usage\n");
    exit(1);
    
}

function next_opt(&$opt, &$val, &$args) {
    global $argv;
    
    start:
    $opt = null;
    $val = null;
    
    if (count($argv) == 0) {
        return false;
    }
    
    $arg = array_shift($argv);
    //echo "arg: $arg\n";
    if ($arg == "--") {
        while (count($argv) > 0)
            $args[] = array_shift($argv);
            
        return false;
    }
    else if (strpos($arg, '--') === 0) {
        
        $eqpos = strpos($arg, '=');
        if ($eqpos !== false) {
            
            $opt = substr($arg, 2, $eqpos-2);
            $val = substr($arg, $eqpos+1);
        }
        else {
            $opt = substr($arg, 2);
            
            if (count($argv) > 0 && strpos($argv[0], "-") !== 0) {
                $val = array_shift($argv);
            }
        }
    }
    else if (strpos($arg, '-') === 0 && strlen($arg) > 1) {
        $opt = $arg[1];
        
        $eqpos = strpos($arg, '=');
        if ($eqpos !== false) {
            $val = substr($arg, $eqpos+1);
        } else {
            $val = false;
        }
//         else {
//             if (strlen($arg) == 2 && count($argv) > 0 && strpos($argv[0], "-") !== 0) {
//                 $val = array_shift($argv);
//             }
//             else {
//                 $val = substr($arg, 2);
//             }
//         }

    }
    else {
        //echo "shifting $arg\n";
        $args[] =  $arg;
        goto start;
    }
    
    return true;
}

function get_token_from_cache(&$db, $scope, $login_hint) {
    $data = @$db[$scope . "#" . $login_hint];
    
    if ($data) {
        $token = new Token();
        
        $token->access_token  = $data["access_token"];
        $token->refresh_token = $data["refresh_token"];
        $token->expires_at    = $data["expires_at"];
        $token->login_hint    = $login_hint;
        $token->scope         = $scope;
        
        return $token;
    }
    
    return false;
}

function save_db($db) {
    global $dbpath;
    file_put_contents($dbpath, json_encode($db, JSON_PRETTY_PRINT) . "\n");
}

function cache_tokens(&$db, $scope, $login_hint, $tokens) {
    
}

function make_auth_url($scope, $login_hint, $redirect_uri, $xsrf) {
    global $client_id;
    
    $scope = preg_replace('/\+/', ' ', $scope);
    $auth_params = array(
        "response_type" => "code",
        "client_id" => $client_id,
        "redirect_uri" => $redirect_uri,
        "scope" => $scope,
        "access_type" => "offline",
        "approval_prompt" => "auto",
        "state" => $xsrf
    );

    if ($login_hint) {
        $auth_params["login_hint"] = $login_hint;
    }

    return "https://accounts.google.com/o/oauth2/auth?" . http_build_query($auth_params);
}

//function make_token_url($)

function open_db() {
    global $dbpath;
    
    if (!file_exists($dbpath)) {
        file_put_contents($dbpath, "{}");
    }
    
    $db = json_decode(file_get_contents($dbpath), true);
    
    if (!$db) {
        file_put_contents($dbpath, "{}");
    }
    
    return $db;
}

function open_browser($url) {
    shell_exec("x-www-browser --new-window " . escapeshellarg($url));
}

function http_server_start(&$socket, &$port) {
    $socket = stream_socket_server("tcp://localhost:0");
    preg_match('/:(\d+)$/', stream_socket_get_name($socket, false), $matches);
    $port = intval($matches[1]);
}

function http_server_recv($server) {
    $conn = stream_socket_accept($server);
    $buff = "";

    do {
        $buff .= fread($conn, 1024*8);
    } while (!preg_match('/\r?\n\r?\n/', $buff));
    
    info("Got request: $buff");

    fwrite($conn, "HTTP/1.0 200 OK\r\n" .
                "Connection: close\r\n" .
                "Expires: -1\r\n".
                "Content-Type: text/html\r\n" .
                "\r\n" .
                "<h1>OK.</h1>\n".
                "You can close this tab now.\n
                <script>open('', '_self', ''); close()</script>");
    fclose($conn);
    
    return $buff;

}

function parse_http_response($data) {
    preg_match('/^GET\s+\/\?(\S+)\s+HTTP\/\S+\r?\n/', $data, $matches);
    parse_str($matches[1], $params);
    return $params;
}

function http_post($url, $data) {
    info("POST URL: $url");
    info("POST DATA: $data");
    $curl = curl_init();
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    
    $output = curl_exec($curl);
    
    info("POST RESULT: $output");
    //$output = curl_exec($curl);
    //info("POST RESULT: $output");
    curl_close($curl);
    
    return $output;
}

function exchange_token($code, $redirect_uri) {
    global $client_secret;
    global $client_id;
    
    $params = array(
        "code" => $code,
        "redirect_uri" => $redirect_uri,
        "client_id" => $client_id,
        "client_secret" => $client_secret,
        "grant_type" => "authorization_code"
    );

    $url = "https://accounts.google.com/o/oauth2/token";
    $data = http_build_query($params);
    
    $response = json_decode(http_post($url, $data), true);
    
    return $response;
}

function info($str) {
    global $verbose;
    if ($verbose) {
        fwrite(STDERR, "$str\n");
    }
}
