<?php
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use Sop\CryptoBridge\Crypto;
use Sop\PKCS5\PBES2;
use Sop\PKCS5\PRF\HMACSHA1;

/**
 * @group pbe
 */
class PBES2Test extends PHPUnit_Framework_TestCase
{
    private static $_pbe;
    public static function setUpBeforeClass()
    {
        self::$_pbe = new PBES2(new HMACSHA1(),
            new DESCBCAlgorithmIdentifier("12345678"), "salt", 1,
            Crypto::getDefault());
    }
    public static function tearDownAfterClass()
    {
        self::$_pbe = null;
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testDecryptInvalidPadding()
    {
        static $password = "password";
        $data = self::$_pbe->encrypt("test", $password);
        $data = substr_replace($data, "\0\0\0\0", -4, 4);
        self::$_pbe->decrypt($data, $password);
    }
}
