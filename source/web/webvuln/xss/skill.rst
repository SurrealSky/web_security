挖掘技巧
================================


基础
--------------------------------
挖掘此类漏洞，依旧要遵循亘古不变的原则，观察我们的输入“输入“和“输出”位置，对于CRLF则是观察返回的各种类型的协议头.

1、尝试插入 ``<u>test</u>`` , ``<h1>test</h1>`` 等观察是否转义。

2、观察输出是否在返回头中，查看输入，可能是在 **URL值** 和 **参数** 、 **cookie头** 中。在过往的挖掘过程中，最常见的两种情况是使用输入参数创建 Cookie和302跳转location处。

3、提交%0D%0A字符，验证服务器是否响应%0D%0A，若过滤可以通过双重编码绕过。

4、漏洞利用，使杀伤最大化，将漏洞转化为HTML注入，XSS，缓存等。


bookmark checklist
--------------------------------
+ notify 
    - ``javascript:((url)=>fetch(url).then((response)=>response.text()).then((scriptInString)=>eval(scriptInString))/*.then(scriptInString =>new Function(scriptInString)())*/)(`https://gist.githubusercontent.com/AzrizHaziq/adcfdbf12c3b30b6523495e19f282b58/raw/a959157530b4c282aae0386fda1b3c3b1656bb7d/notify.js`);``
+ input框注入
    - ``javascript:(function(){for(var t=document.getElementsByTagName("input"),e=0;e<t.length;e++) "text"==t[e].getAttribute("type")&&(t[e].value='"><img src=x onerror=alert("XSS");>')})();``
+ 每个元素增加颜色
    - ``javascript:(function(){var elements=document.querySelectorAll('*');for(var i=0;i<elements.length;i++){elements[i].style.outline='1px solid #'+(~~(Math.random()*(1<<24))).toString(16)}})();``
+ 密码显示
    - ``javascript:(function(){var s,F,j,f,i; s = ""; F = document.forms; for(j=0; j<F.length; ++j) { f = F[j]; for (i=0; i<f.length; ++i) { if (f[i].type.toLowerCase() == "password") s += f[i].value + "\n"; } } if (s) alert("Passwords in forms on this page:\n\n" + s); else alert("No passwords found on this page.");})();``
+ cookie查看
    - ``javascript:alert(document.cookie);``
+ 查看时间监听器
    ::

        javascript:(function(){
        // 查看元素的事件监听器（有限支持）
        var elements = document.querySelectorAll('*');
        var result = [];
        
        for(var i = 0; i < elements.length; i++) {
            var elem = elements[i];
            var attributes = elem.attributes;
            
            for(var j = 0; j < attributes.length; j++) {
                var attr = attributes[j];
                if(attr.name.startsWith('on')) {
                    result.push({
                        element: elem.tagName + (elem.id ? '#' + elem.id : '') + (elem.className ? '.' + elem.className : ''),
                        event: attr.name,
                        handler: attr.value
                    });
                }
            }
        }
        
        console.log('内联事件监听器:', result);
        alert('找到 ' + result.length + ' 个内联事件监听器，详情请查看控制台');
        })()
+ Next.js website
    - ``javascript​:console.log(__BUILD_MANIFEST.sortedPages.join('\n'));``