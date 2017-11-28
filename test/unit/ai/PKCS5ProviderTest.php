<?php

use PHPUnit\Framework\TestCase;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PKCS5AlgorithmIdentifierProvider;

class PKCS5ProviderTest extends TestCase
{
    /**
     * @expectedException UnexpectedValueException
     */
    public function testUnsupportedOID()
    {
        $provider = new PKCS5AlgorithmIdentifierProvider();
        $provider->getClassByOID("1.3.6.1.3");
    }
}
