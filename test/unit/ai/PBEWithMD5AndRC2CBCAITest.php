<?php

use ASN1\Type\Constructed\Sequence;
use PHPUnit\Framework\TestCase;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithMD5AndRC2CBCAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 */
class PBEWithMD5AndRC2CBCAITest extends TestCase
{
    const SALT = "12345678";
    
    const COUNT = 4096;
    
    /**
     *
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new PBEWithMD5AndRC2CBCAlgorithmIdentifier(self::SALT, self::COUNT);
        $seq = $ai->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }
    
    /**
     * @depends testEncode
     *
     * @param Sequence $seq
     * @return AlgorithmIdentifier
     */
    public function testDecode(Sequence $seq)
    {
        $ai = PBEAlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(PBEWithMD5AndRC2CBCAlgorithmIdentifier::class,
            $ai);
        return $ai;
    }
    
    /**
     * @depends testDecode
     *
     * @param PBEWithMD5AndRC2CBCAlgorithmIdentifier $ai
     */
    public function testSalt(PBEWithMD5AndRC2CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(self::SALT, $ai->salt());
    }
    
    /**
     * @depends testDecode
     *
     * @param PBEWithMD5AndRC2CBCAlgorithmIdentifier $ai
     */
    public function testIterationCount(
        PBEWithMD5AndRC2CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(self::COUNT, $ai->iterationCount());
    }
    
    /**
     * @depends testDecode
     *
     * @param AlgorithmIdentifier $algo
     */
    public function testName(AlgorithmIdentifier $algo)
    {
        $this->assertInternalType("string", $algo->name());
    }
}
