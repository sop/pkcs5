<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\CipherAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBES2AlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBKDF2AlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class PBES2AITest extends TestCase
{
    /**
     * @return Sequence
     */
    public function testEncode()
    {
        $kdf = new PBKDF2AlgorithmIdentifier('12345678', 1024);
        $es = new DESCBCAlgorithmIdentifier('fedcba98');
        $ai = new PBES2AlgorithmIdentifier($kdf, $es);
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
        $this->assertInstanceOf(PBES2AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testDecode
     *
     * @param PBES2AlgorithmIdentifier $ai
     */
    public function testKDF(PBES2AlgorithmIdentifier $ai)
    {
        $this->assertInstanceOf(PBKDF2AlgorithmIdentifier::class,
            $ai->kdfAlgorithmIdentifier());
    }

    /**
     * @depends testDecode
     *
     * @param PBES2AlgorithmIdentifier $ai
     */
    public function testES(PBES2AlgorithmIdentifier $ai)
    {
        $this->assertInstanceOf(CipherAlgorithmIdentifier::class,
            $ai->esAlgorithmIdentifier());
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
        PBEAlgorithmIdentifier::fromASN1($seq);
    }

    /**
     * @depends testEncode
     *
     * @param Sequence $seq
     */
    public function testDecodeInvalidKDFFail(Sequence $seq)
    {
        $params = $seq->at(1)->asSequence();
        $ai = $params->at(0)->asSequence()
            ->withReplaced(0, new ObjectIdentifier('1.3.6.1.3'));
        $params = $params->withReplaced(0, $ai);
        $seq = $seq->withReplaced(1, $params);
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('KDF algorithm');
        PBEAlgorithmIdentifier::fromASN1($seq);
    }

    /**
     * @depends testEncode
     *
     * @param Sequence $seq
     */
    public function testDecodeInvalidCipherFail(Sequence $seq)
    {
        $params = $seq->at(1)->asSequence();
        $ai = $params->at(1)->asSequence()
            ->withReplaced(0, new ObjectIdentifier('1.3.6.1.3'));
        $params = $params->withReplaced(1, $ai);
        $seq = $seq->withReplaced(1, $params);
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('ES algorithm');
        PBEAlgorithmIdentifier::fromASN1($seq);
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
