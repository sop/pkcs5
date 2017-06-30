<?php

namespace Sop\PKCS5\ASN1\AlgorithmIdentifier;

use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifierProvider;

class PKCS5AlgorithmIdentifierProvider implements AlgorithmIdentifierProvider
{
    /**
     * Mapping from OID to class name.
     *
     * @var array
     */
    const MAP_OID_TO_CLASS = array(
        /* @formatter:off */
        PBEAlgorithmIdentifier::OID_PBE_WITH_MD2_AND_DES_CBC => PBEWithMD2AndDESCBCAlgorithmIdentifier::class,
        PBEAlgorithmIdentifier::OID_PBE_WITH_MD2_AND_RC2_CBC => PBEWithMD2AndRC2CBCAlgorithmIdentifier::class,
        PBEAlgorithmIdentifier::OID_PBE_WITH_MD5_AND_DES_CBC => PBEWithMD5AndDESCBCAlgorithmIdentifier::class,
        PBEAlgorithmIdentifier::OID_PBE_WITH_MD5_AND_RC2_CBC => PBEWithMD5AndRC2CBCAlgorithmIdentifier::class,
        PBEAlgorithmIdentifier::OID_PBE_WITH_SHA1_AND_DES_CBC => PBEWithSHA1AndDESCBCAlgorithmIdentifier::class,
        PBEAlgorithmIdentifier::OID_PBE_WITH_SHA1_AND_RC2_CBC => PBEWithSHA1AndRC2CBCAlgorithmIdentifier::class,
        PBEAlgorithmIdentifier::OID_PBE_WITH_SHA1_AND_RC2_40_CBC => PBEWithSHA1And40BitRC2CBCAlgorithmIdentifier::class,
        PBEAlgorithmIdentifier::OID_PBE_WITH_SHA1_AND_3KEY_3DES_CBC => PBEWithSHA1And3Key3DESCBCAlgorithmIdentifier::class,
        PBEAlgorithmIdentifier::OID_PBES2 => PBES2AlgorithmIdentifier::class,
        PBKDF2AlgorithmIdentifier::OID_PBKDF2 => PBKDF2AlgorithmIdentifier::class
        /* @formatter:on */
    );
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function supportsOID($oid)
    {
        return array_key_exists($oid, self::MAP_OID_TO_CLASS);
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function getClassByOID($oid)
    {
        if (!$this->supportsOID($oid)) {
            throw new \UnexpectedValueException(
                "Algorithm $oid is not supported.");
        }
        return self::MAP_OID_TO_CLASS[$oid];
    }
}
