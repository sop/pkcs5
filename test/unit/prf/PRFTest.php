<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\RFC4231HMACAlgorithmIdentifier;
use Sop\PKCS5\PRF\HMACSHA1;
use Sop\PKCS5\PRF\PRF;

/**
 * @group pbe
 * @group prf
 *
 * @internal
 */
class PRFTest extends TestCase
{
    public function testInvoke()
    {
        $prf = new HMACSHA1();
        $result = $prf('arg1', 'arg2');
        $this->assertEquals($prf->length(), strlen($result));
    }

    public function testUnsupportedAlgo()
    {
        $algo = new PRFTest_UnsupportedAlgo();
        $this->expectException(\UnexpectedValueException::class);
        PRF::fromAlgorithmIdentifier($algo);
    }
}

class PRFTest_UnsupportedAlgo extends RFC4231HMACAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = '1.3.6.1.3';
    }

    public function name(): string
    {
        return '';
    }
}
