<?php
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use Sop\CryptoBridge\Crypto;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBES2AlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithMD2AndDESCBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithMD2AndRC2CBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithMD5AndDESCBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithMD5AndRC2CBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithSHA1And3Key3DESCBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithSHA1And40BitRC2CBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithSHA1AndDESCBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithSHA1AndRC2CBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBKDF2AlgorithmIdentifier;
use Sop\PKCS5\PBEScheme;

/**
 * @group pbe
 */
class PBESchemeTest extends PHPUnit_Framework_TestCase
{
    /**
     * @dataProvider provideFromAlgo
     *
     * @param PBEAlgorithmIdentifier $algo
     */
    public function testFromAlgo(PBEAlgorithmIdentifier $algo)
    {
        $pbe = PBEScheme::fromAlgorithmIdentifier($algo, Crypto::getDefault());
        $this->assertInstanceOf(PBEScheme::class, $pbe);
    }
    public function provideFromAlgo()
    {
        static $salt = "12345678";
        static $iter = 8;
        return array(
            /* @formatter:off */
            [new PBEWithMD2AndDESCBCAlgorithmIdentifier($salt, $iter)],
            [new PBEWithMD2AndRC2CBCAlgorithmIdentifier($salt, $iter)],
            [new PBEWithMD5AndDESCBCAlgorithmIdentifier($salt, $iter)],
            [new PBEWithMD5AndRC2CBCAlgorithmIdentifier($salt, $iter)],
            [new PBEWithSHA1AndDESCBCAlgorithmIdentifier($salt, $iter)],
            [new PBEWithSHA1AndRC2CBCAlgorithmIdentifier($salt, $iter)],
            [new PBEWithSHA1And40BitRC2CBCAlgorithmIdentifier($salt, $iter)],
            [new PBEWithSHA1And3Key3DESCBCAlgorithmIdentifier($salt, $iter)],
            [new PBES2AlgorithmIdentifier(
                new PBKDF2AlgorithmIdentifier($salt, $iter),
                new DESCBCAlgorithmIdentifier())]
            /* @formatter:on */
        );
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testUnsupportedAlgo()
    {
        PBEScheme::fromAlgorithmIdentifier(
            new PBESchemeTest_UnsupportedPBEAlgo("12345678", 8),
            Crypto::getDefault());
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidPBES2AlgoFail()
    {
        PBEScheme::fromAlgorithmIdentifier(
            new PBESchemeTest_InvalidPBES2Algo("12345678", 8),
            Crypto::getDefault());
    }
}

class PBESchemeTest_UnsupportedPBEAlgo extends PBEAlgorithmIdentifier
{
    public function __construct($salt, $iteration_count)
    {
        parent::__construct($salt, $iteration_count);
        $this->_oid = "1.3.6.1.3";
    }
    public function name()
    {
        return "";
    }
    protected function _paramsASN1()
    {
        return null;
    }
}

class PBESchemeTest_InvalidPBES2Algo extends PBEAlgorithmIdentifier
{
    public function __construct($salt, $iteration_count)
    {
        parent::__construct($salt, $iteration_count);
        $this->_oid = PBEAlgorithmIdentifier::OID_PBES2;
    }
    public function name()
    {
        return "";
    }
    protected function _paramsASN1()
    {
        return null;
    }
}