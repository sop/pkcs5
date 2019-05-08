<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithSHA1And40BitRC2CBCAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class PBEWithSHA1And40BitRC2CBCAITest extends TestCase
{
    const SALT = '12345678';

    const COUNT = 4096;

    /**
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new PBEWithSHA1And40BitRC2CBCAlgorithmIdentifier(self::SALT,
            self::COUNT);
        $seq = $ai->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    /**
     * @depends testEncode
     *
     * @param Sequence $seq
     *
     * @return AlgorithmIdentifier
     */
    public function testDecode(Sequence $seq)
    {
        $ai = PBEAlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(
            PBEWithSHA1And40BitRC2CBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testDecode
     *
     * @param PBEWithSHA1And40BitRC2CBCAlgorithmIdentifier $ai
     */
    public function testSalt(PBEWithSHA1And40BitRC2CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(self::SALT, $ai->salt());
    }

    /**
     * @depends testDecode
     *
     * @param PBEWithSHA1And40BitRC2CBCAlgorithmIdentifier $ai
     */
    public function testIterationCount(
        PBEWithSHA1And40BitRC2CBCAlgorithmIdentifier $ai)
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
        $this->assertIsString($algo->name());
    }
}
