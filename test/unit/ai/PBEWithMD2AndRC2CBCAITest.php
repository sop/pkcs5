<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithMD2AndRC2CBCAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class PBEWithMD2AndRC2CBCAITest extends TestCase
{
    const SALT = '12345678';

    const COUNT = 4096;

    /**
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new PBEWithMD2AndRC2CBCAlgorithmIdentifier(self::SALT, self::COUNT);
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
        $this->assertInstanceOf(PBEWithMD2AndRC2CBCAlgorithmIdentifier::class,
            $ai);
        return $ai;
    }

    /**
     * @depends testDecode
     *
     * @param PBEWithMD2AndRC2CBCAlgorithmIdentifier $ai
     */
    public function testSalt(PBEWithMD2AndRC2CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(self::SALT, $ai->salt());
    }

    /**
     * @depends testDecode
     *
     * @param PBEWithMD2AndRC2CBCAlgorithmIdentifier $ai
     */
    public function testIterationCount(
        PBEWithMD2AndRC2CBCAlgorithmIdentifier $ai)
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
