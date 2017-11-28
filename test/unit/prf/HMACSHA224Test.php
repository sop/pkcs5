<?php

use PHPUnit\Framework\TestCase;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA224AlgorithmIdentifier;
use Sop\PKCS5\PRF\HMACSHA224;
use Sop\PKCS5\PRF\PRF;

/**
 * @group pbe
 * @group prf
 */
class PRFHMACSHA224Test extends TestCase
{
    /**
     *
     * @return PRF
     */
    public function testCreateFromAlgo()
    {
        $algo = new HMACWithSHA224AlgorithmIdentifier();
        $prf = PRF::fromAlgorithmIdentifier($algo);
        $this->assertInstanceOf(HMACSHA224::class, $prf);
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
