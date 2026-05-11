<?php

declare(strict_types=1);

const ROOT_PATH = __DIR__ . '/..';
const DATA_PATH = ROOT_PATH . '/data';
const USERS_FILE = DATA_PATH . '/users.json';
const VAULTS_PATH = ROOT_PATH . '/vaults';
const MIN_PASSWORD_LENGTH = 8;
const ARCHIVE_FOLDER_NAME = 'Archive';

function app_bootstrap(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_set_cookie_params([
            'httponly' => true,
            'samesite' => 'Lax',
            'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        ]);
        session_start();
    }

    foreach ([DATA_PATH, VAULTS_PATH] as $dir) {
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
    }

    if (!is_file(USERS_FILE)) {
        file_put_contents(USERS_FILE, "[]\n", LOCK_EX);
    }

    csrf_token();
}

function read_users(): array
{
    $raw = file_get_contents(USERS_FILE);
    $data = json_decode($raw ?: '[]', true);
    return is_array($data) ? $data : [];
}

function write_users(array $users): void
{
    file_put_contents(USERS_FILE, json_encode(array_values($users), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n", LOCK_EX);
}

function current_user(): ?array
{
    return $_SESSION['user'] ?? null;
}

function is_password_change_required(): bool
{
    return (bool) (current_user()['force_password_change'] ?? false);
}

function set_session_user(array $user): void
{
    $_SESSION['user'] = [
        'id' => $user['id'],
        'username' => $user['username'],
        'role' => $user['role'] ?? 'user',
        'force_password_change' => (bool) ($user['force_password_change'] ?? false),
    ];
}

function csrf_token(): string
{
    if (!isset($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf(?string $token): void
{
    if (!is_string($token) || !hash_equals(csrf_token(), $token)) {
        throw new RuntimeException('Invalid CSRF token.');
    }
}

function require_auth(): void
{
    if (!current_user()) {
        header('Location: ?route=login');
        exit;
    }
}

function require_admin(): void
{
    require_auth();
    $user = current_user();
    if (($user['role'] ?? 'user') !== 'admin') {
        http_response_code(403);
        echo 'Forbidden';
        exit;
    }
}

function find_user_by_username(string $username): ?array
{
    foreach (read_users() as $user) {
        if (($user['username'] ?? '') === $username) {
            return $user;
        }
    }
    return null;
}

function find_user_by_id(string $userId): ?array
{
    foreach (read_users() as $user) {
        if (($user['id'] ?? '') === $userId) {
            return $user;
        }
    }
    return null;
}

function set_user_password(string $userId, string $password, bool $forcePasswordChange): bool
{
    $users = read_users();
    $updated = false;

    foreach ($users as &$user) {
        if (($user['id'] ?? '') !== $userId) {
            continue;
        }
        $user['password_hash'] = password_hash($password, PASSWORD_DEFAULT);
        $user['force_password_change'] = $forcePasswordChange;
        $updated = true;
        break;
    }
    unset($user);

    if ($updated) {
        write_users($users);
    }

    return $updated;
}

function login_user(string $username, string $password): ?string
{
    $user = find_user_by_username(trim($username));
    if (!$user || !password_verify($password, $user['password_hash'] ?? '')) {
        return 'Invalid credentials.';
    }
    if (($user['status'] ?? 'pending') !== 'active') {
        return 'Your account is pending admin approval.';
    }

    set_session_user($user);

    ensure_vault($user['id']);
    return null;
}

function request_account(string $username, string $password): ?string
{
    $username = strtolower(trim($username));
    if (!preg_match('/^[a-z0-9_\-]{3,30}$/', $username)) {
        return 'Username must be 3-30 chars: letters, numbers, _ or -.';
    }
    if (strlen($password) < MIN_PASSWORD_LENGTH) {
        return 'Password must be at least ' . MIN_PASSWORD_LENGTH . ' characters.';
    }

    $users = read_users();
    foreach ($users as $u) {
        if (($u['username'] ?? '') === $username) {
            return 'Username already exists.';
        }
    }

    $user = [
        'id' => $username,
        'username' => $username,
        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
        'status' => 'pending',
        'role' => 'user',
        'created_at' => date(DATE_ATOM),
    ];
    $users[] = $user;
    write_users($users);
    ensure_vault($user['id']);

    return null;
}

function ensure_vault(string $userId): string
{
    $vault = user_vault_path($userId);
    if (!is_dir($vault)) {
        mkdir($vault, 0700, true);
    }

    $structureFile = $vault . '/structure.json';
    if (!is_file($structureFile)) {
        file_put_contents($structureFile, json_encode(['updated_at' => date(DATE_ATOM), 'files' => []], JSON_PRETTY_PRINT) . "\n", LOCK_EX);
    }

    return $vault;
}

function user_vault_path(string $userId): string
{
    $safeId = preg_replace('/[^a-zA-Z0-9_\-]/', '', $userId);
    return VAULTS_PATH . '/' . $safeId;
}

function normalize_note_path(string $path): string
{
    $path = trim(str_replace('\\', '/', $path), '/');
    if ($path === '') {
        return '';
    }

    $parts = array_values(array_filter(explode('/', $path), static fn($part) => $part !== '' && $part !== '.'));
    foreach ($parts as $part) {
        if ($part === '..') {
            throw new RuntimeException('Invalid path.');
        }
    }

    return implode('/', $parts);
}

function note_absolute_path(string $userId, string $path): string
{
    $vault = realpath(user_vault_path($userId));
    if ($vault === false) {
        throw new RuntimeException('Vault not found.');
    }

    $normalized = normalize_note_path($path);
    $target = $vault . '/' . $normalized;

    if (!str_ends_with($target, '.md')) {
        $target .= '.md';
    }

    return $target;
}

function create_note(string $userId, string $notePath): ?string
{
    $notePath = normalize_note_path($notePath);
    if ($notePath === '') {
        return 'Note path is required.';
    }

    $fullPath = note_absolute_path($userId, $notePath);
    if (is_file($fullPath)) {
        return 'Note already exists.';
    }

    $dir = dirname($fullPath);
    if (!is_dir($dir)) {
        mkdir($dir, 0700, true);
    }

    file_put_contents($fullPath, "---\ntags: []\n---\n\n# " . basename($notePath) . "\n", LOCK_EX);
    rebuild_structure($userId);

    return null;
}

function create_folder(string $userId, string $folderPath): ?string
{
    $folderPath = normalize_note_path($folderPath);
    if ($folderPath === '') {
        return 'Folder path is required.';
    }

    $vault = realpath(user_vault_path($userId));
    if ($vault === false) {
        return 'Vault not found.';
    }

    $fullPath = $vault . '/' . $folderPath;
    if (is_dir($fullPath)) {
        return 'Folder already exists.';
    }

    if (is_file($fullPath)) {
        return 'A note already exists with this path.';
    }

    if (!mkdir($fullPath, 0700, true) && !is_dir($fullPath)) {
        return 'Unable to create folder.';
    }

    rebuild_structure($userId);
    return null;
}

function save_note(string $userId, string $notePath, string $content): ?string
{
    $fullPath = note_absolute_path($userId, $notePath);
    $vault = realpath(user_vault_path($userId));
    $targetDir = realpath(dirname($fullPath));

    if ($targetDir === false) {
        mkdir(dirname($fullPath), 0700, true);
        $targetDir = realpath(dirname($fullPath));
    }

    if ($vault === false || $targetDir === false || !str_starts_with($targetDir, $vault)) {
        return 'Invalid note location.';
    }

    file_put_contents($fullPath, $content, LOCK_EX);
    rebuild_structure($userId);

    return null;
}

function note_last_saved_at_utc(string $userId, string $notePath): ?string
{
    $fullPath = note_absolute_path($userId, $notePath);
    if (!is_file($fullPath)) {
        return null;
    }

    $mtime = filemtime($fullPath);
    if ($mtime === false) {
        return null;
    }

    return gmdate('c', $mtime);
}

function move_note_destination_path(string $fromPath, string $destinationFolder): string
{
    $fromPath = normalize_note_path($fromPath);
    $destinationFolder = normalize_note_path($destinationFolder);
    $fileName = pathinfo($fromPath, PATHINFO_BASENAME);
    return $destinationFolder === '' ? $fileName : $destinationFolder . '/' . $fileName;
}

function move_note(string $userId, string $fromPath, string $destinationFolder): ?string
{
    $fromPath = normalize_note_path($fromPath);
    if ($fromPath === '') {
        return 'Source note path is required.';
    }

    $targetPath = move_note_destination_path($fromPath, $destinationFolder);
    if ($targetPath === $fromPath) {
        return null;
    }

    $vault = realpath(user_vault_path($userId));
    $sourceFullPath = note_absolute_path($userId, $fromPath);
    if (!is_file($sourceFullPath)) {
        return 'Source note not found.';
    }
    $sourceRealPath = realpath($sourceFullPath);

    $targetFullPath = note_absolute_path($userId, $targetPath);
    $targetDir = dirname($targetFullPath);
    if (!is_dir($targetDir)) {
        mkdir($targetDir, 0700, true);
    }
    $targetDirRealPath = realpath($targetDir);

    if (
        $vault === false
        || $sourceRealPath === false
        || $targetDirRealPath === false
        || !str_starts_with($sourceRealPath, $vault)
        || !str_starts_with($targetDirRealPath, $vault)
    ) {
        return 'Invalid note location.';
    }

    if (is_file($targetFullPath)) {
        return 'A note with this name already exists in the destination folder.';
    }

    if (!rename($sourceFullPath, $targetFullPath)) {
        return 'Unable to move note.';
    }

    remove_empty_parent_folders($sourceFullPath, $vault);

    rebuild_structure($userId);
    return null;
}

function delete_note(string $userId, string $notePath): ?string
{
    $notePath = normalize_note_path($notePath);
    if ($notePath === '') {
        return 'Note path is required.';
    }

    $vault = realpath(user_vault_path($userId));
    $fullPath = note_absolute_path($userId, $notePath);
    if (!is_file($fullPath)) {
        return 'Note not found.';
    }
    $sourceRealPath = realpath($fullPath);

    if ($vault === false || $sourceRealPath === false || !str_starts_with($sourceRealPath, $vault)) {
        return 'Invalid note location.';
    }

    if (!unlink($fullPath)) {
        return 'Unable to delete note.';
    }

    remove_empty_parent_folders($fullPath, $vault);
    rebuild_structure($userId);
    return null;
}

function archive_note(string $userId, string $notePath): ?string
{
    $notePath = normalize_note_path($notePath);
    if ($notePath === '') {
        return 'Note path is required.';
    }
    if ($notePath === ARCHIVE_FOLDER_NAME || str_starts_with($notePath, ARCHIVE_FOLDER_NAME . '/')) {
        return 'Note is already archived.';
    }

    return move_note($userId, $notePath, ARCHIVE_FOLDER_NAME);
}

function read_note(string $userId, string $notePath): ?string
{
    $fullPath = note_absolute_path($userId, $notePath);
    if (!is_file($fullPath)) {
        return null;
    }

    return file_get_contents($fullPath) ?: '';
}

function rebuild_structure(string $userId): array
{
    $vault = user_vault_path($userId);
    $files = [];
    $folders = [];

    $iter = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($vault, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($iter as $fileInfo) {
        $relative = str_replace('\\', '/', str_replace($vault . '/', '', $fileInfo->getPathname()));
        if ($relative === '' || $relative === 'structure.json') {
            continue;
        }

        if ($fileInfo->isDir()) {
            $folders[] = $relative;
            continue;
        }

        if (!$fileInfo->isFile()) {
            continue;
        }

        if ($fileInfo->getExtension() !== 'md') {
            continue;
        }

        $files[] = $relative;
    }

    sort($files);
    sort($folders);

    $structure = [
        'updated_at' => date(DATE_ATOM),
        'files' => $files,
        'folders' => $folders,
    ];

    $writeResult = file_put_contents($vault . '/structure.json', json_encode($structure, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n", LOCK_EX);
    if ($writeResult === false) {
        $lastError = error_get_last();
        $details = is_array($lastError) && isset($lastError['message']) ? ' (' . $lastError['message'] . ')' : '';
        throw new RuntimeException('Failed to write structure.json.' . $details);
    }

    return $structure;
}

function get_structure(string $userId): array
{
    $vault = ensure_vault($userId);
    $structurePath = $vault . '/structure.json';

    if (!is_file($structurePath)) {
        return rebuild_structure($userId);
    }

    $data = json_decode(file_get_contents($structurePath) ?: '{}', true);
    if (
        !is_array($data)
        || !isset($data['files'])
        || !is_array($data['files'])
        || !isset($data['folders'])
        || !is_array($data['folders'])
    ) {
        return rebuild_structure($userId);
    }

    return $data;
}

function remove_empty_parent_folders(string $path, string $vault): void
{
    $cursor = dirname($path);
    while ($cursor !== $vault && str_starts_with($cursor, $vault)) {
        if (!is_dir($cursor)) {
            break;
        }
        $entries = scandir($cursor);
        if ($entries === false || count(array_diff($entries, ['.', '..'])) !== 0) {
            break;
        }
        if (!rmdir($cursor)) {
            break;
        }
        $cursor = dirname($cursor);
    }
}

function extract_tags(string $content): array
{
    if (!preg_match('/^---\s*\n(.*?)\n---\s*\n/s', $content, $m)) {
        return [];
    }

    if (!preg_match('/tags:\s*\[(.*?)\]/', $m[1], $tagsMatch)) {
        return [];
    }

    $raw = array_filter(array_map('trim', explode(',', $tagsMatch[1])));
    return array_values(array_unique(array_map(static fn($tag) => ltrim(trim($tag, " \t\n\r\0\x0B\"'"), '#'), $raw)));
}

function all_tags(string $userId): array
{
    $structure = get_structure($userId);
    $tags = [];

    foreach ($structure['files'] as $file) {
        $content = read_note($userId, $file);
        if ($content === null) {
            continue;
        }

        foreach (extract_tags($content) as $tag) {
            $tags[$tag] = ($tags[$tag] ?? 0) + 1;
        }
    }

    ksort($tags);
    return $tags;
}

function search_notes(string $userId, string $query, string $scope = 'global', string $folder = ''): array
{
    $query = trim($query);
    if ($query === '') {
        return [];
    }

    $folder = trim(normalize_note_path($folder));
    $structure = get_structure($userId);
    $results = [];

    foreach ($structure['files'] as $file) {
        if ($scope === 'folder' && $folder !== '' && !str_starts_with($file, $folder . '/')) {
            continue;
        }

        $content = read_note($userId, $file);
        if ($content !== null && stripos($content, $query) !== false) {
            $results[] = $file;
        }
    }

    return $results;
}

function folder_size_bytes(string $path): int
{
    if (!is_dir($path)) {
        return 0;
    }

    $bytes = 0;
    $iter = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS));
    foreach ($iter as $info) {
        if ($info->isFile()) {
            $bytes += $info->getSize();
        }
    }

    return $bytes;
}

function format_bytes(int $bytes): string
{
    $units = ['B', 'KB', 'MB', 'GB'];
    $i = 0;
    $value = (float)$bytes;
    while ($value >= 1024 && $i < count($units) - 1) {
        $value /= 1024;
        $i++;
    }
    return number_format($value, 1) . ' ' . $units[$i];
}
