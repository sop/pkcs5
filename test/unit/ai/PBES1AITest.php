<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithMD5AndDESCBCAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class PBES1AITest extends TestCase
{
    public function testInvalidSalt()
    {
        $this->expectException(\UnexpectedValueException::class);
        new PBEWithMD5AndDESCBCAlgorithmIdentifier('1234', 1);
    }

    public function testNoParamsFail()
    {
        $ai = new PBEWithMD5AndDESCBCAlgorithmIdentifier('12345678', 1);
        $seq = $ai->toASN1()->withoutElement(1);
        $this->expectException(\UnexpectedValueException::class);
        PBEAlgorithmIdentifier::fromASN1($seq);
    }
}
