<?php

use PHPUnit\Framework\TestCase;
use Sop\PKCS5\Padding;

/**
 * @group pbe
 */
class PaddingTest extends TestCase
{
    protected static $_padding;
    
    public static function setUpBeforeClass()
    {
        self::$_padding = new Padding(8);
    }
    
    public static function tearDownAfterClass()
    {
        self::$_padding = null;
    }
    
    /**
     *
     * @return string
     */
    public function testAddPadding()
    {
        $str = self::$_padding->add("test");
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
        $this->assertEquals("test", $result);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testNoPadding()
    {
        self::$_padding->remove("");
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testPaddingTooLong()
    {
        self::$_padding->remove(hex2bin("badcafeeffffffff"));
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testPaddingLargerThanBlock()
    {
        self::$_padding->remove("testtes" . str_repeat("\x9", 9));
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidPadding()
    {
        self::$_padding->remove(hex2bin("badcafeeffffff04"));
    }
}
