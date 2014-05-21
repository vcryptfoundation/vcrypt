<?php
$funcname = 'vcrypt_get_error';
$varname = 'errordesc\[\]';

$data = `gcc -E $argv[1]`;

if (preg_match("/$funcname\s*\([^)]*\)\s*({.*^})/ms", $data, $m))
{
	$funcdata = $m[1];
}
else
	die ("no matches, func\n");

unset($m);
if (preg_match("/^.*$varname.*$/m", $funcdata, $m))
{
	$vardec = $m[0];
}
else
	die ("no matches, var\n");

// find pad
unset($m);
if(preg_match("/^.*}/", $vardec, $m))
{
	$pad_b = $m[0];
}

unset($m);
if (preg_match("/^$pad_b.*^$pad_b/msU", $funcdata, $m))
	$vardata = $m[0];
else
	die("no match\n");

unset($m);
if(preg_match_all("/{\s*(\w[^,]+)\s*,.*(\".*\").*}/msU", $vardata, $m) == 0)
	die("no match\n");

$out = fopen($argv[2], 'w');

fputs($out, "enum VCRYPT_ERROR {\n");
foreach($m[1] as $k=>$v)
{
	fputs($out,  "\t// {$m[2][$k]}\n");
	fputs($out, "\t$v, \n");
}

fputs($out, "};\n");
fclose($out);


