<?php

$request_uri = $_SERVER['REQUEST_URI'];
$uri_parts = explode('/', $request_uri);
$endpoint = implode('/', array_slice($uri_parts, 2));

include 'api.php';

// POST book
if (strpos($endpoint, 'website/api/v1/book') !== false) {
  header('Content-Type: application/json');
  $csrfToken = end($uri_parts);
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    post_book($csrfToken);
  } else {
    http_response_code(405);
    echo json_encode(['error' => 'Invalid request method for this endpoint']);
  }
} 
// POST waybill
else if (strpos($endpoint, 'website/api/v1/waybill') !== false) {
  header('Content-Type: application/json');
  $csrfToken = end($uri_parts);
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    post_waybill($csrfToken);
  } else {
    http_response_code(405);
    echo json_encode(['error' => 'Invalid request method for this endpoint']);
  }
} 
// POST inquiries
else if (strpos($endpoint, 'website/api/v1/inquiry') !== false) {
  header('Content-Type: application/json');
  $csrfToken = end($uri_parts);
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    post_inquiry($csrfToken);
  } else {
    http_response_code(405);
    echo json_encode(['error' => 'Invalid request method for this endpoint']);
  }
} 
// GET csrf token
else if ($endpoint === 'website/api/v1/security/csrf-token') {
  header('Content-Type: application/json');
  if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    generateCsrfToken();
  } else {
    http_response_code(405);
    echo json_encode(['error' => 'Invalid request method for this endpoint']);
  }
}
else {
  header('Content-Type: application/json');
  http_response_code(404);
  echo json_encode(['message' => 'Endpoint not found']);
}
?>