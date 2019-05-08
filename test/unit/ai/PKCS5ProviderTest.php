<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PKCS5AlgorithmIdentifierProvider;

/**
 * @internal
 */
class PKCS5ProviderTest extends TestCase
{
    public function testUnsupportedOID()
    {
        $provider = new PKCS5AlgorithmIdentifierProvider();
        $this->expectException(\UnexpectedValueException::class);
        $provider->getClassByOID('1.3.6.1.3');
    }
}
