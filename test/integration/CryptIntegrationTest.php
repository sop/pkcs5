<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBES2AlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithMD2AndDESCBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithMD2AndRC2CBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithMD5AndDESCBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithMD5AndRC2CBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithSHA1AndDESCBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithSHA1AndRC2CBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBKDF2AlgorithmIdentifier;
use Sop\PKCS5\PBEScheme;

/**
 * @internal
 */
class CryptIntegrationTest extends TestCase
{
    const DATA = 'testdata';

    const PASSWORD = 'password';

    /**
     * @dataProvider provideEncryptDecrypt
     *
     * @param PBEAlgorithmIdentifier $algo
     */
    public function testEncryptDecrypt(PBEAlgorithmIdentifier $algo)
    {
        $scheme = PBEScheme::fromAlgorithmIdentifier($algo, Crypto::getDefault());
        $ciphertext = $scheme->encrypt(self::DATA, self::PASSWORD);
        $this->assertNotEquals(self::DATA, $ciphertext);
        $plaintext = $scheme->decrypt($ciphertext, self::PASSWORD);
        $this->assertEquals(self::DATA, $plaintext);
    }

    /**
     * @return PBEAlgorithmIdentifier[]
     */
    public function provideEncryptDecrypt()
    {
        static $salt = '12345678';
        static $iv = '09876543';
        static $iter = 8;
        return [
            [new PBEWithMD2AndDESCBCAlgorithmIdentifier($salt, $iter)],
            [new PBEWithMD2AndRC2CBCAlgorithmIdentifier($salt, $iter)],
            [new PBEWithMD5AndDESCBCAlgorithmIdentifier($salt, $iter)],
            [new PBEWithMD5AndRC2CBCAlgorithmIdentifier($salt, $iter)],
            [new PBEWithSHA1AndDESCBCAlgorithmIdentifier($salt, $iter)],
            [new PBEWithSHA1AndRC2CBCAlgorithmIdentifier($salt, $iter)],
            [new PBES2AlgorithmIdentifier(
                new PBKDF2AlgorithmIdentifier($salt, $iter),
                new DESCBCAlgorithmIdentifier($iv))],
        ];
    }
}
