<?php

use PHPUnit\Framework\TestCase;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA1AlgorithmIdentifier;
use Sop\PKCS5\PRF\HMACSHA1;
use Sop\PKCS5\PRF\PRF;

/**
 * @group pbe
 * @group prf
 */
class PRFHMACSHA1Test extends TestCase
{
    /**
     *
     * @return PRF
     */
    public function testCreateFromAlgo()
    {
        $algo = new HMACWithSHA1AlgorithmIdentifier();
        $prf = PRF::fromAlgorithmIdentifier($algo);
        $this->assertInstanceOf(HMACSHA1::class, $prf);
        return $prf;
    }
    
    /**
     * @depends testCreateFromAlgo
     *
     * @param PRF $prf
     */
    public function testInvoke(PRF $prf)
    {
        $hash = $prf("a1", "a2");
        $this->assertEquals($prf->length(), strlen($hash));
    }
}
