代码执行
========================================

简介
----------------------------------------
应用程序在调用一些能够将字符串转换为代码的函数（如PHP中的eval）时，没有考虑用户是否控制这个字符串，将造成代码执行漏洞。很难通过黑盒查找漏洞，大部分都是根据源代码判断代码执行漏洞。

相关函数
----------------------------------------
- eval()将字符串当作函数执行

	.. code-block:: php
		
		<?php
		eval (echo "hello";);
		?>
		
- assert():判断是否为字符串，是则当成代码执行

	.. code-block:: php
		
		<?php
		$a = 'assert';
		$a(phpinfo());
		?>
		
- call_user_func:回调函数,可以使用is_callable查看是否可以进行调用

	.. code-block:: php
	
		<?php
		highlight_file(__FILE__);
		$a = 'system';
		$b = 'pwd';
		call_user_func($a,$b);
		call_user_func('eval','phpinfo()');
		?>

- call_user_fuc_array:回调函数，参数为数组

	.. code-block:: php
	
		<?php
		highlight_file(__FILE__);
		$array[0] = $_POST['a'];
		call_user_func_array("assert",$array); 
		?>

- create_function:创建匿名函数,args是要创建的函数的参数，code是函数内的代码

	.. code-block:: php
	
		<?php
		highlight_file(__FILE__);
		$a = create_function('$code', 'echo $code');
		$b = 'hello';
		$a($b);
		
		$a = 'phpinfo();';
		$b = create_function(" ", $a);
		$b();
		?>
		
- preg_replace:当为/e时代码会执行，前提是不超过php7

	.. code-block:: php
	
		<?php
		highlight_file(__FILE__);
		$a = 'phpinfo()';
		$b = preg_replace("/abc/e", $a, 'abc');
		?>

- array_map:为数组的每个元素应用回调函数

	.. code-block:: php
	
		<?php
		highlight_file(__FILE__);
		$a = $_GET['a'];
		$b = $_GET['b'];
		$array[0] = $b;
		$c = array_map($a,$array);
		?>

- array_filter:依次将array数组中的每个值传递到 callback 函数。

	.. code-block:: php
	
		<?php
		highlight_file(__FILE__);
		$array[0] = $_GET['a'];
		array_filter($array,'assert');
		?>
		
- usort:使用自定义函数对数组进行排序

	.. code-block:: php
	
		<?php
		highlight_file(__FILE__);
		usort(...$_GET);
		#usort($_GET[1],'assert');
		?>
		
		1[]=phpinfo()&1[]=123&2[]=assert
		
- ${}:中间的php代码将会被解析

	.. code-block::
	
		<?php
		highlight_file(__FILE__);
		${phpinfo()};
		?>
		
		<?php
		highlight_file(__FILE__);
		$price = $_GET['price'];
		$code = 'echo $name.'.'的价格是'.$price.';';
		$b = create_function('$name', $code);
		$b('iphone');
		?>
		
		payload为：123;}phpinfo();/*

