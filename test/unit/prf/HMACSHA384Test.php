<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA384AlgorithmIdentifier;
use Sop\PKCS5\PRF\HMACSHA384;
use Sop\PKCS5\PRF\PRF;

/**
 * @group pbe
 * @group prf
 *
 * @internal
 */
class PRFHMACSHA384Test extends TestCase
{
    /**
     * @return PRF
     */
    public function testCreateFromAlgo()
    {
        $algo = new HMACWithSHA384AlgorithmIdentifier();
        $prf = PRF::fromAlgorithmIdentifier($algo);
        $this->assertInstanceOf(HMACSHA384::class, $prf);
        return $prf;
    }

    /**
     * @depends testCreateFromAlgo
     *
     * @param PRF $prf
     */
    public function testInvoke(PRF $prf)
    {
        $hash = $prf('a1', 'a2');
        $this->assertEquals($prf->length(), strlen($hash));
    }
}
