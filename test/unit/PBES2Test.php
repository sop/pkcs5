<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use Sop\PKCS5\PBES2;
use Sop\PKCS5\PRF\HMACSHA1;

/**
 * @group pbe
 *
 * @internal
 */
class PBES2Test extends TestCase
{
    private static $_pbe;

    public static function setUpBeforeClass(): void
    {
        self::$_pbe = new PBES2(new HMACSHA1(),
            new DESCBCAlgorithmIdentifier('12345678'), 'salt', 1,
            Crypto::getDefault());
    }

    public static function tearDownAfterClass(): void
    {
        self::$_pbe = null;
    }

    public function testDecryptInvalidPadding()
    {
        static $password = 'password';
        $data = self::$_pbe->encrypt('test', $password);
        $data = substr_replace($data, "\0\0\0\0", -4, 4);
        $this->expectException(\UnexpectedValueException::class);
        self::$_pbe->decrypt($data, $password);
    }
}
