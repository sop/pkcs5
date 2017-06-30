<?php
use ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithSHA1And3Key3DESCBCAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 */
class PBEWithSHA1And3Key3DESCBCAITest extends PHPUnit_Framework_TestCase
{
    const SALT = "12345678";
    const COUNT = 4096;
    
    /**
     *
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new PBEWithSHA1And3Key3DESCBCAlgorithmIdentifier(self::SALT,
            self::COUNT);
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
        $this->assertInstanceOf(
            PBEWithSHA1And3Key3DESCBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }
    
    /**
     * @depends testDecode
     *
     * @param PBEWithSHA1And3Key3DESCBCAlgorithmIdentifier $ai
     */
    public function testSalt(PBEWithSHA1And3Key3DESCBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(self::SALT, $ai->salt());
    }
    
    /**
     * @depends testDecode
     *
     * @param PBEWithSHA1And3Key3DESCBCAlgorithmIdentifier $ai
     */
    public function testIterationCount(
        PBEWithSHA1And3Key3DESCBCAlgorithmIdentifier $ai)
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
