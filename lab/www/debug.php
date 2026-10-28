<?php
header('Content-Type: text/plain; charset=utf-8');
echo "post_keys=" . implode(',', array_keys($_POST)) . "\n";
echo "files=" . count($_FILES) . "\n";
if (isset($_FILES['f'])) echo "file_name=" . $_FILES['f']['name'] . "\n";
echo "sess_id=" . session_id() . "\n";
foreach ($_POST as $k => $v) { if (strlen($v) < 40) echo "$k=$v\n"; }
