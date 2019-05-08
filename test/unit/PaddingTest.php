<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\PKCS5\Padding;

/**
 * @group pbe
 *
 * @internal
 */
class PaddingTest extends TestCase
{
    protected static $_padding;

    public static function setUpBeforeClass(): void
    {
        self::$_padding = new Padding(8);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_padding = null;
    }

    /**
     * @return string
     */
    public function testAddPadding()
    {
        $str = self::$_padding->add('test');
        $this->assertEquals("test\x4\x4\x4\x4", $str);
        return $str;
    }

    /**
     * @depends testAddPadding
     *
     * @param string $str
     */
    public function testRemovePadding($str)
    {
        $result = self::$_padding->remove($str);
        $this->assertEquals('test', $result);
    }

    public function testNoPadding()
    {
        $this->expectException(\UnexpectedValueException::class);
        self::$_padding->remove('');
    }

    public function testPaddingTooLong()
    {
        $this->expectException(\UnexpectedValueException::class);
        self::$_padding->remove(hex2bin('badcafeeffffffff'));
    }

    public function testPaddingLargerThanBlock()
    {
        $this->expectException(\UnexpectedValueException::class);
        self::$_padding->remove('testtes' . str_repeat("\x9", 9));
    }

    public function testInvalidPadding()
    {
        $this->expectException(\UnexpectedValueException::class);
        self::$_padding->remove(hex2bin('badcafeeffffff04'));
    }
}
