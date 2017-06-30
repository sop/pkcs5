<?php
use ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithMD2AndDESCBCAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 */
class PBEWithMD2AndDESCBCAITest extends PHPUnit_Framework_TestCase
{
    const SALT = "12345678";
    const COUNT = 4096;
    
    /**
     *
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new PBEWithMD2AndDESCBCAlgorithmIdentifier(self::SALT, self::COUNT);
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
        $this->assertInstanceOf(PBEWithMD2AndDESCBCAlgorithmIdentifier::class,
            $ai);
        return $ai;
    }
    
    /**
     * @depends testDecode
     *
     * @param PBEWithMD2AndDESCBCAlgorithmIdentifier $ai
     */
    public function testSalt(PBEWithMD2AndDESCBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(self::SALT, $ai->salt());
    }
    
    /**
     * @depends testDecode
     *
     * @param PBEWithMD2AndDESCBCAlgorithmIdentifier $ai
     */
    public function testIterationCount(
        PBEWithMD2AndDESCBCAlgorithmIdentifier $ai)
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
