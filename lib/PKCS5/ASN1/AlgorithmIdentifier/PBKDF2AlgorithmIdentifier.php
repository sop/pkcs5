<?php

declare(strict_types = 1);

namespace Sop\PKCS5\ASN1\AlgorithmIdentifier;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifierFactory;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\PRFAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA1AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

/*
From RFC 2898 - A.2   PBKDF2:

PBKDF2-params ::= SEQUENCE {
    salt CHOICE {
        specified OCTET STRING,
        otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
    },
    iterationCount INTEGER (1..MAX),
    keyLength INTEGER (1..MAX) OPTIONAL,
    prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT
    algid-hmacWithSHA1 }
*/

/**
 * Algorithm identifier for PBKDF2 key derivation function.
 *
 * @see https://tools.ietf.org/html/rfc2898#section-5.2
 * @see https://tools.ietf.org/html/rfc2898#appendix-A.2
 */
class PBKDF2AlgorithmIdentifier extends SpecificAlgorithmIdentifier
{
    const OID_PBKDF2 = '1.2.840.113549.1.5.12';

    /**
     * Explicitly specified salt.
     *
     * @var string
     */
    protected $_specifiedSalt;

    /**
     * Iteration count.
     *
     * @var int
     */
    protected $_iterationCount;

    /**
     * Key length.
     *
     * @var null|int
     */
    protected $_keyLength;

    /**
     * Pseudorandom function algorithm identifier.
     *
     * @var PRFAlgorithmIdentifier
     */
    protected $_prfAlgo;

    /**
     * Constructor.
     *
     * @param string                      $salt            Salt
     * @param int                         $iteration_count Iteration count
     * @param null|int                    $key_length      Optional key length
     * @param null|PRFAlgorithmIdentifier $prf_algo        Default to HMAC-SHA1
     */
    public function __construct(string $salt, int $iteration_count,
        ?int $key_length = null, ?PRFAlgorithmIdentifier $prf_algo = null)
    {
        $this->_oid = self::OID_PBKDF2;
        $this->_specifiedSalt = $salt;
        $this->_iterationCount = $iteration_count;
        $this->_keyLength = $key_length;
        $this->_prfAlgo = isset($prf_algo) ? $prf_algo : new HMACWithSHA1AlgorithmIdentifier();
    }

    /**
     * @param Sequence $seq
     *
     * @return AlgorithmIdentifier
     */
    public static function fromASN1(Sequence $seq): AlgorithmIdentifier
    {
        return (new AlgorithmIdentifierFactory(
            new PKCS5AlgorithmIdentifierProvider()))->parse($seq);
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'pBKDF2';
    }

    /**
     * {@inheritdoc}
     *
     * @throws \RuntimeException
     *
     * @return self
     */
    public static function fromASN1Params(
        ?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        if (!isset($params)) {
            throw new \UnexpectedValueException('No parameters.');
        }
        $seq = $params->asSequence();
        $el = $seq->at(0);
        switch ($el->tag()) {
            // specified
            case Element::TYPE_OCTET_STRING:
                $salt = $el->asOctetString()->string();
                break;
            // otherSource
            case Element::TYPE_SEQUENCE:
                AlgorithmIdentifier::fromASN1($el->asSequence());
                throw new \RuntimeException('otherSource not implemented.');
            default:
                throw new \UnexpectedValueException('Invalid salt encoding.');
        }
        $iteration_count = $seq->at(1)
            ->asInteger()
            ->intNumber();
        $key_length = null;
        $prf_algo = null;
        $idx = 2;
        if ($seq->has($idx, Element::TYPE_INTEGER)) {
            $key_length = $seq->at($idx++)
                ->asInteger()
                ->intNumber();
        }
        if ($seq->has($idx, Element::TYPE_SEQUENCE)) {
            $prf_algo = AlgorithmIdentifier::fromASN1(
                $seq->at($idx++)->asSequence());
            if (!($prf_algo instanceof PRFAlgorithmIdentifier)) {
                throw new \UnexpectedValueException(
                    sprintf('%s is not a supported pseudorandom function.',
                        $prf_algo->name()));
            }
        }
        return new self($salt, $iteration_count, $key_length, $prf_algo);
    }

    /**
     * Get salt.
     *
     * @return string
     */
    public function salt(): string
    {
        return $this->_specifiedSalt;
    }

    /**
     * Get iteration count.
     *
     * @return int
     */
    public function iterationCount(): int
    {
        return $this->_iterationCount;
    }

    /**
     * Whether key length is present.
     *
     * @return bool
     */
    public function hasKeyLength(): bool
    {
        return isset($this->_keyLength);
    }

    /**
     * Get key length.
     *
     * @throws \LogicException
     *
     * @return int
     */
    public function keyLength(): int
    {
        if (!$this->hasKeyLength()) {
            throw new \LogicException('keyLength not set.');
        }
        return $this->_keyLength;
    }

    /**
     * Get pseudorandom function algorithm.
     *
     * @return PRFAlgorithmIdentifier
     */
    public function prfAlgorithmIdentifier(): PRFAlgorithmIdentifier
    {
        return $this->_prfAlgo;
    }

    /**
     * {@inheritdoc}
     *
     * @return Sequence
     */
    protected function _paramsASN1(): ?Element
    {
        $elements = [];
        $elements[] = new OctetString($this->_specifiedSalt);
        $elements[] = new Integer($this->_iterationCount);
        if (isset($this->_keyLength)) {
            $elements[] = new Integer($this->_keyLength);
        }
        if (AlgorithmIdentifier::OID_HMAC_WITH_SHA1 != $this->_prfAlgo->oid()) {
            $elements[] = $this->_prfAlgo->toASN1();
        }
        return new Sequence(...$elements);
    }
}
