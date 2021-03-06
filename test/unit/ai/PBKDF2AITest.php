<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\PRFAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA256AlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBKDF2AlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class PBEKDF2AITest extends TestCase
{
    const SALT = '12345678';

    const COUNT = 4096;

    const KEY_LEN = 8;

    /**
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new PBKDF2AlgorithmIdentifier(self::SALT, self::COUNT,
            self::KEY_LEN);
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
        $ai = PBKDF2AlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(PBKDF2AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testDecode
     *
     * @param PBKDF2AlgorithmIdentifier $ai
     */
    public function testSalt(PBKDF2AlgorithmIdentifier $ai)
    {
        $this->assertEquals(self::SALT, $ai->salt());
    }

    /**
     * @depends testDecode
     *
     * @param PBKDF2AlgorithmIdentifier $ai
     */
    public function testIterationCount(PBKDF2AlgorithmIdentifier $ai)
    {
        $this->assertEquals(self::COUNT, $ai->iterationCount());
    }

    /**
     * @depends testDecode
     *
     * @param PBKDF2AlgorithmIdentifier $ai
     */
    public function testKeyLength(PBKDF2AlgorithmIdentifier $ai)
    {
        $this->assertEquals(self::KEY_LEN, $ai->keyLength());
    }

    public function testKeyLengthFails()
    {
        $ai = new PBKDF2AlgorithmIdentifier("\0", 1);
        $this->expectException(\LogicException::class);
        $ai->keyLength();
    }

    /**
     * @depends testDecode
     *
     * @param PBKDF2AlgorithmIdentifier $ai
     */
    public function testPRF(PBKDF2AlgorithmIdentifier $ai)
    {
        $algo = $ai->prfAlgorithmIdentifier();
        $this->assertInstanceOf(PRFAlgorithmIdentifier::class, $algo);
    }

    /**
     * @depends testEncode
     *
     * @param Sequence $seq
     */
    public function testDecodeNoParamsFail(Sequence $seq)
    {
        $seq = $seq->withoutElement(1);
        $this->expectException(\UnexpectedValueException::class);
        PBKDF2AlgorithmIdentifier::fromASN1($seq);
    }

    /**
     * @return Sequence
     */
    public function testEncodeExplicitPRF()
    {
        $ai = new PBKDF2AlgorithmIdentifier(self::SALT, self::COUNT,
            self::KEY_LEN, new HMACWithSHA256AlgorithmIdentifier());
        $seq = $ai->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    /**
     * @depends testEncodeExplicitPRF
     *
     * @param Sequence $seq
     */
    public function testDecodeExplicitPRF(Sequence $seq)
    {
        $ai = PBKDF2AlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(PBKDF2AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testDecodeExplicitPRF
     *
     * @param PBKDF2AlgorithmIdentifier $ai
     */
    public function testExplicitPRF(PBKDF2AlgorithmIdentifier $ai)
    {
        $this->assertInstanceOf(HMACWithSHA256AlgorithmIdentifier::class,
            $ai->prfAlgorithmIdentifier());
    }

    /**
     * @depends testEncode
     *
     * @param Sequence $seq
     */
    public function testInvalidPRF(Sequence $seq)
    {
        $prf = new Sequence(new ObjectIdentifier('1.3.6.1.3'));
        $params = $seq->at(1)->asSequence();
        $params = $params->withInserted(3, $prf);
        $seq = $seq->withReplaced(1, $params);
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('not a supported pseudorandom function');
        PBKDF2AlgorithmIdentifier::fromASN1($seq);
    }

    /**
     * @depends testEncode
     *
     * @param Sequence $seq
     */
    public function testDecodeOtherSaltSourceFail(Sequence $seq)
    {
        $algo = new GenericAlgorithmIdentifier('1.3.6.1.3');
        $params = $seq->at(1)->asSequence();
        $params = $params->withReplaced(0, $algo->toASN1());
        $seq = $seq->withReplaced(1, $params);
        $this->expectException(\RuntimeException::class);
        PBKDF2AlgorithmIdentifier::fromASN1($seq);
    }

    /**
     * @depends testEncode
     *
     * @param Sequence $seq
     */
    public function testDecodeInvalidSaltChoiceFail(Sequence $seq)
    {
        $params = $seq->at(1)->asSequence();
        $params = $params->withReplaced(0, new NullType());
        $seq = $seq->withReplaced(1, $params);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid salt encoding');
        PBKDF2AlgorithmIdentifier::fromASN1($seq);
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
