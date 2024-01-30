<?php
// Security Headers
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, *");

include 'config.php';
session_start();

// Ito yung magkicreate ng csrf token
function generateCsrfToken() {
  if (!isset($_SESSION['csrf_token']) || !isset($_SESSION['csrf_token_expire']) || $_SESSION['csrf_token_expire'] < time()) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    $_SESSION['csrf_token_expire'] = time() + 300;
  }
  echo json_encode([
    'csrfToken' => $_SESSION['csrf_token'],
    'expiryDate' => $_SESSION['csrf_token_expire'],
  ]);
}

// Ito yung magbavalidate ng token
function validateCsrfToken($sentToken) {
  return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $sentToken);
}

// Ichicheck kung yung csrf token ba is existing
function checkCsrfToken($sentCsrfToken) {
  if (!$sentCsrfToken || !validateCsrfToken($sentCsrfToken)) {
      http_response_code(403);
      echo json_encode(['error' => 'CSRF Token Validation Failed']);
      exit;
  }
}

// POST method ng pag iinsert ng book
function post_book($csrfToken) {
  global $pdo;

  // Defined variable
  $booking_id = 'BI-' . mt_rand(1000000000, 9999999999);
  $full_name = filter_input(INPUT_POST, 'full_name', FILTER_SANITIZE_STRING);
  $email_address = filter_input(INPUT_POST, 'email_address', FILTER_SANITIZE_EMAIL);
  $contact_number = filter_input(INPUT_POST, 'contact_number', FILTER_SANITIZE_STRING);
  $complete_address = filter_input(INPUT_POST, 'complete_address', FILTER_SANITIZE_STRING);
  $details = filter_input(INPUT_POST, 'details', FILTER_SANITIZE_STRING);

  // Ichicheck kung invalid ba yung csrf token
  if ($csrfToken !== $_SESSION['csrf_token']) {
      http_response_code(403);
      echo json_encode(['error' => 'CSRF Token Validation Failed']);
      exit;
  }

  // Kapag merong isang field yung missing
  if (!$csrfToken || !$full_name || !$email_address || !$contact_number || !$complete_address || !$details) {
      http_response_code(400);
      echo json_encode(['error' => 'Invalid input data']);
      exit;
  }

  // Taga check kung yung booking_id is nageexist naba
  $existingBookingQuery = $pdo->prepare("SELECT COUNT(*) FROM book WHERE booking_id = ?");
  $existingBookingQuery->execute([$booking_id]);
  $existingBookingCount = $existingBookingQuery->fetchColumn();

  if ($existingBookingCount > 0) {
      http_response_code(400);
      echo json_encode(['error' => 'Booking ID already exists']);
      exit;
  }

  $sql = "INSERT INTO book (booking_id, full_name, email_address, contact_number, complete_address, details) 
          VALUES (?, ?, ?, ?, ?, ?)";

  $stmt = $pdo->prepare($sql);
  $stmt->bindParam(1, $booking_id);
  $stmt->bindParam(2, $full_name);
  $stmt->bindParam(3, $email_address);
  $stmt->bindParam(4, $contact_number);
  $stmt->bindParam(5, $complete_address);
  $stmt->bindParam(6, $details);

  if ($stmt->execute()) {
      echo json_encode(['message' => 'Booking successfully submitted!']);
  } else {
      echo json_encode(['error' => '[Error] Failed to submit your booking.']);
  }

  $stmt->closeCursor();
}

// POST method ng pagiinsert ng e-waybill
function post_waybill($csrfToken) {
  global $pdo;

  // Defined variable
  $e_waybill = 'EWB-' . mt_rand(1000000000, 9999999999);
  $sender = filter_input(INPUT_POST, 'sender', FILTER_SANITIZE_STRING);
  $sender_phone = filter_input(INPUT_POST, 'sender_phone', FILTER_SANITIZE_STRING);
  $sender_address = filter_input(INPUT_POST, 'sender_address', FILTER_SANITIZE_STRING);
  $consignee = filter_input(INPUT_POST, 'consignee', FILTER_SANITIZE_STRING);
  $consignee_phone = filter_input(INPUT_POST, 'consignee_phone', FILTER_SANITIZE_STRING);
  $consignee_address = filter_input(INPUT_POST, 'consignee_address', FILTER_SANITIZE_STRING);
  $size = filter_input(INPUT_POST, 'size', FILTER_SANITIZE_STRING);

  // Ichicheck kung invalid ba yung csrf token
  if ($csrfToken !== $_SESSION['csrf_token']) {
      http_response_code(403);
      echo json_encode(['error' => 'CSRF Token Validation Failed']);
      exit;
  }

  // Kapag merong isang field yung missing
  if (!$csrfToken || !$e_waybill || !$sender || !$sender_phone || !$sender_address || !$consignee || !$consignee_phone || !$consignee_address || !$size) {
      http_response_code(400);
      echo json_encode(['error' => 'Invalid input data']);
      exit;
  }

  // Taga check kung yung booking_id is nageexist naba
  $existingWaybillQuery = $pdo->prepare("SELECT COUNT(*) FROM waybill WHERE e_waybill = ?");
  $existingWaybillQuery->execute([$e_waybill]);
  $existingWaybillCount = $existingWaybillQuery->fetchColumn();

  if ($existingWaybillCount > 0) {
      http_response_code(400);
      echo json_encode(['error' => 'E-waybill already exists']);
      exit;
  }

  $sql = "INSERT INTO waybill (e_waybill, sender, sender_phone, sender_address, consignee, consignee_phone, consignee_address, size) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

  $stmt = $pdo->prepare($sql);
  $stmt->bindParam(1, $e_waybill);
  $stmt->bindParam(2, $sender);
  $stmt->bindParam(3, $sender_phone);
  $stmt->bindParam(4, $sender_address);
  $stmt->bindParam(5, $consignee);
  $stmt->bindParam(6, $consignee_phone);
  $stmt->bindParam(7, $consignee_address);
  $stmt->bindParam(8, $size);

  if ($stmt->execute()) {
      echo json_encode(['message' => 'E-waybill successfully submitted!']);
  } else {
      echo json_encode(['error' => '[Error] Failed to submit the e-waybill.']);
  }

  $stmt->closeCursor();
}

// POST method ng pagiinsert ng inquiry
function post_inquiry($csrfToken) {
  global $pdo;

  // Defined variables
  $inquiry_id = 'CI-' . mt_rand(1000000000, 9999999999);
  $name = filter_input(INPUT_POST, 'name', FILTER_SANITIZE_STRING);
  $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
  $subject = filter_input(INPUT_POST, 'subject', FILTER_SANITIZE_STRING);
  $message = filter_input(INPUT_POST, 'message', FILTER_SANITIZE_STRING);

  // Ichicheck kung invalid ba yung csrf token
  if ($csrfToken !== $_SESSION['csrf_token']) {
      http_response_code(403);
      echo json_encode(['error' => 'CSRF Token Validation Failed']);
      exit;
  }

  // Kapag merong isang field yung missing o mali yung email format
  if (!$csrfToken || !$name || !filter_var($email, FILTER_VALIDATE_EMAIL) || !$subject || !$message) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid input data or wrong email format']);
    exit;
  }

  // Taga check kung yung inquiry_id is nageexist naba
  $existingInquiryQuery = $pdo->prepare("SELECT COUNT(*) FROM inquiry WHERE inquiry_id = ?");
  $existingInquiryQuery->execute([$inquiry_id]);
  $existingInquiryCount = $existingInquiryQuery->fetchColumn();

  if ($existingInquiryCount > 0) {
      http_response_code(400);
      echo json_encode(['error' => 'Inquiry ID already exists']);
      exit;
  }

  $sql = "INSERT INTO inquiry (inquiry_id, name, email, subject, message) 
          VALUES (?, ?, ?, ?, ?)";

  $stmt = $pdo->prepare($sql);
  $stmt->bindParam(1, $inquiry_id);
  $stmt->bindParam(2, $name);
  $stmt->bindParam(3, $email);
  $stmt->bindParam(4, $subject);
  $stmt->bindParam(5, $message);

  if ($stmt->execute()) {
      echo json_encode(['message' => 'Inquiry successfully submitted!']);
  } else {
      echo json_encode(['error' => '[Error] Failed to submit the inquiry.']);
  }

  $stmt->closeCursor();
}

?>