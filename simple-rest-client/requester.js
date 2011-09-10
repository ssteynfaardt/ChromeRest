// Status codes as per rfc2616
// @see http://tools.ietf.org/html/rfc2616#section-10
var statusCodes = new Array();
// Informational 1xx
statusCodes[100] = 'Continue';
statusCodes[101] = 'Switching Protocols';
// Successful 2xx
statusCodes[200] = 'OK';
statusCodes[201] = 'Created';
statusCodes[202] = 'Accepted';
statusCodes[203] = 'Non-Authoritative Information';
statusCodes[204] = 'No Content';
statusCodes[205] = 'Reset Content';
statusCodes[206] = 'Partial Content';
// Redirection 3xx
statusCodes[300] = 'Multiple Choices';
statusCodes[301] = 'Moved Permanently';
statusCodes[302] = 'Found';
statusCodes[303] = 'See Other';
statusCodes[304] = 'Not Modified';
statusCodes[305] = 'Use Proxy';
statusCodes[307] = 'Temporary Redirect';
// Client Error 4xx
statusCodes[400] = 'Bad Request';
statusCodes[401] = 'Unauthorized';
statusCodes[402] = 'Payment Required';
statusCodes[403] = 'Forbidden';
statusCodes[404] = 'Not Found';
statusCodes[405] = 'Method Not Allowed';
statusCodes[406] = 'Not Acceptable';
statusCodes[407] = 'Proxy Authentication Required';
statusCodes[408] = 'Request Time-out';
statusCodes[409] = 'Conflict';
statusCodes[410] = 'Gone';
statusCodes[411] = 'Length Required';
statusCodes[412] = 'Precondition Failed';
statusCodes[413] = 'Request Entity Too Large';  
statusCodes[414] = 'Request-URI Too Long';
statusCodes[415] = 'Unsupported Media Type';
statusCodes[416] = 'Requested range not satisfiable';
statusCodes[417] = 'Expectation Failed';
// Server Error 5xx
statusCodes[500] = 'Internal Server Error';
statusCodes[501] = 'Not Implemented';
statusCodes[502] = 'Bad Gateway';
statusCodes[503] = 'Service Unavailable';
statusCodes[504] = 'Gateway Time-out';
statusCodes[505] = 'HTTP Version not supported';

var defaultHeight = 23;
//var defaultHeightPx = defaultHeight+"px";
 
//even listener to simply make the request when ctrl + enter is pressed
document.addEventListener("keydown", function (e) 
{
    if (e.keyCode === 13 && e.ctrlKey) 
    {
        e.preventDefault();
        sendRequest(); 
    }
}, false);


//changes the size of the text area so the all text is visible.
function grow(id) {
    var textarea = document.getElementById(id);
    var newHeight = textarea.scrollHeight;
    var currentHeight = textarea.clientHeight;
    if (newHeight == 0 || $("#"+id).val() == "") {
        newHeight = defaultHeight;
    }
    textarea.style.height = newHeight + 'px';
}

function clearFields() {
    $("#response").css("display", "");
    $("#loader").css("display", "");
    $("#responsePrint").css("display", "none");

    $("#responseStatus").html("");
    $("#responseHeaders").val("");
    $("#codeData").text("");

    $("#responseHeaders").height(defaultHeight);
    $("#headers").height(defaultHeight);
    $("#postputdata").height(defaultHeight);

    $("#respHeaders").css("display", "none");
    $("#respData").css("display", "none");
    $("#respData").css("display", "none");
    $("#postputaction").css("display", "none");
}

function saveCurrentQuery(){
    
    var restCall = {
        "url": $("#url").val(), 
        "method":$(':selected').val(),
        "headers":$('#headers').val(),
        "postdata":$('#postputdata').val()
    };
    localStorage.setItem("lastCall", JSON.stringify(restCall));
}

// Tilde should be allowed unescaped in future versions of PHP (as reflected below), but if you want to reflect current
// PHP behavior, you would need to add ".replace(/~/g, '%7E');" to the following.
function rawurlencode (str) {
	str = (str + '').toString();
	return encodeURIComponent(str).replace(/!/g, '%21').replace(/'/g, '%27').replace(/\(/g, '%28').
	replace(/\)/g, '%29').replace(/\*/g, '%2A');
}

function uniqid (prefix, more_entropy) {
    if (typeof prefix == 'undefined') {
        prefix = "";
    }

    var retId;
    var formatSeed = function (seed, reqWidth) {
        seed = parseInt(seed, 10).toString(16); // to hex str
        if (reqWidth < seed.length) { // so long we split
            return seed.slice(seed.length - reqWidth);
        }
        if (reqWidth > seed.length) { // so short we pad
            return Array(1 + (reqWidth - seed.length)).join('0') + seed;
        }
        return seed;
    };

    // BEGIN REDUNDANT
    if (!this.php_js) {
        this.php_js = {};
    }
    // END REDUNDANT
    if (!this.php_js.uniqidSeed) { // init seed with big random int
        this.php_js.uniqidSeed = Math.floor(Math.random() * 0x75bcd15);
    }
    this.php_js.uniqidSeed++;

    retId = prefix; // start with prefix, add current milliseconds hex string
    retId += formatSeed(parseInt(new Date().getTime() / 1000, 10), 8);
    retId += formatSeed(this.php_js.uniqidSeed, 5); // add seed hex string
    if (more_entropy) {
        // for more entropy we add a float lower to 10
        retId += (Math.random() * 10).toFixed(8).toString();
    }

    return retId;
}

function authenticationHeader(consumerKey,consumerSecret){
	var timestamp = Math.round(new Date().getTime() / 1000),
	nonce = uniqid(),
	key = rawurlencode(consumerSecret),
	sig = 'oauth_consumer_key="'+consumerKey+'"&oauth_nonce="'+nonce+'"&oauth_timestamp="'+timestamp+'"';
	signature = rawurlencode(b64_hmac_sha1(key,rawurlencode(sig))+'=');
	headers=new Array();
	
	headers.push('Authorization: oauth_signature="'+signature+'",oauth_nonce="'+nonce+'",oauth_timestamp="'+timestamp+'",oauth_consumer_key="'+consumerKey+'"');
	headers.push('Content-Type: application/x-www-form-urlencoded');
	return headers;
}

function sendAuthenticationHeader(){
	var xhr = new XMLHttpRequest();
	xhr.onreadystatechange = readAuthenticationResponse;
	try {
		var authorizeURL = 'http://'+$("#url").val().match(/:\/\/(www\.)?(.[^/:]+)/)[2]+'/oauth/authorize';
		xhr.open('POST',authorizeURL, true);
		var headers = authenticationHeader('57b6c9c6612b83e77381402cde3882ab04d5bbb0f','cadf46959433fc38aec49812753dd460');
		for (var i = 0; i < headers.length; i++) {
			var header = headers[i].split(": ");
			if (header[1])
				xhr.setRequestHeader(header[0],header[1]);
		}
		xhr.send("");
	}
	catch(e){
		smoke.alert('Failed to send oAuth request');
	}
}

function sendRequestToken(requestToken,username,password){
	var xhr = new XMLHttpRequest();
	xhr.onreadystatechange = readAccessTokenResponse;
	try {
		var authorizeURL = 'http://'+$("#url").val().match(/:\/\/(www\.)?(.[^/:]+)/)[2]+'/oauth/authorize?request_token='+requestToken+'&username='+username+'&password='+password+'&ttl=7200';
		xhr.open('POST',authorizeURL, true);
		var headers = new Array();
		headers.push('Content-Type: application/x-www-form-urlencoded');
		for (var i = 0; i < headers.length; i++) {
			var header = headers[i].split(": ");
			if (header[1])
				xhr.setRequestHeader(header[0],header[1]);
		}
		xhr.send("");
	}
	catch(e){
		smoke.alert('Failed to send oAuth request');
	}
}

function readAuthenticationResponse() {
	if (this.readyState == 4) {
		try {
			var response = JSON.parse(this.responseText);
			if(response.request_token)
			{
				var username = 'vanwykcorinne@telkomsa.net',
				password = 'test';
				sendRequestToken(response.request_token,username,password)
			}
			else{
				smoke.alert('no request token was found');
			}
		}
		catch(e) {
		}
	}
}

function readAccessTokenResponse(){
	if (this.readyState == 4) {
		try {
			var response = JSON.parse(this.responseText);
			if(response.access_token)
			{
				var token = 'access_token: '+response.access_token;
				$("#headers").val(token);
				//sendRequestToken(response.request_token,username,password)
			}
			else{
				smoke.alert('no access token was found');
			}
		}
		catch(e) {
		}
	}
}


function loadLastQuery(){
    var lastCall = JSON.parse(localStorage.getItem("lastCall"));
    if(lastCall){
        $('#url').val(lastCall.url);
        $(':selected').val(lastCall.method);
        $('#headers').val(lastCall.headers);
        $('#postputdata').val(lastCall.postdata);
        grow('headers');
        grow('postputdata');
    }
}

function clearLastQuery(){
    localStorage.removeItem('lastCall');
}


function sendRequest() {
    var regexp = /(ftp|http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?/;

    if(regexp.test($("#url").val())) {
        clearFields();
        var xhr = new XMLHttpRequest();
        xhr.onreadystatechange = readResponse;
        try {
            saveCurrentQuery();
            xhr.open($(':selected').val().toUpperCase(), $("#url").val(), true);
            var headers = $("#headers").val();
            headers = headers.split("\n");
            for (var i = 0; i < headers.length; i++) {
                var header = headers[i].split(": ");
                if (header[1])
                    xhr.setRequestHeader(header[0],header[1]);
            }
            if(jQuery.inArray($(':selected').val(), ["post", "put"]) > -1) {
                xhr.send($("#postputdata").val());
            } else {
                xhr.send("");
            }
        }
        catch(e){
            //console.log(e);
            //$("#responseStatus").html("<span style=\"color:#FF0000\">"+chrome.i18n.getMessage("bad_request")+"</span>");
            $("#respHeaders").css("display", "none");
            $("#respData").css("display", "none");

            $("#loader").css("display", "none");
            $("#responsePrint").css("display", "");
        }
    } else {
  
        if($("#url").val() == "")
            smoke.alert('Please provide a URL to call');
        else
            smoke.alert('Please provide a valid URL');
        //console.log("no uri");
        //$("#responseStatus").html("<span style=\"color:#FF0000\">"+chrome.i18n.getMessage("bad_request")+"</span>");
        $("#respHeaders").css("display", "none");
        $("#respData").css("display", "none");

        $("#loader").css("display", "none");
        $("#responsePrint").css("display", "");
    }
}

function readResponse() {
    grow('headers');
    grow('postputdata');
    if (this.readyState == 4) {
        try {
            if(this.status == 0) {
                throw('Status = 0');
            }
            $("#responseStatus").html(this.status+' '+statusCodes[this.status]);
            $("#responseHeaders").val(jQuery.trim(this.getAllResponseHeaders()));
            var debugurl = /X-Debug-URL: (.*)/i.exec($("#responseHeaders").val());
            if (debugurl) {
                $("#debugLink").attr('href', debugurl[1]).html(debugurl[1]);
                $("#debugLinks").css("display", "");
            }
            var json = false;
            if(json = isValidJson(jQuery.trim(this.responseText))){
                $("#codeData").html(json);
                $("#fullscreenCode").html($("#codeData").html());
            }
            else{
                $("#codeData").html(jQuery.trim(this.responseText).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'));
                $.chili.options.automatic.active = false;
                $.chili.options.decoration.lineNumbers = false;
                var $chili = $('#codeData').chili();
                $("#fullscreenCode").html($("#codeData").html());
            }
            
            $("#respHeaders").css("display", "");
            $("#respData").css("display", "");

            $("#loader").css("display", "none");
            $("#responsePrint").css("display", "");
            $("#fullscreen").width(window.innerWidth-20);
            $("#fullscreen").height(window.innerHeight-20);
            $("#fullscreenClose").css("left",window.innerWidth-60+"px");

            grow('responseHeaders');
        }
        catch(e) {
            $("#responseStatus").html("No response.");
            $("#respHeaders").css("display", "none");
            $("#respData").css("display", "none");

            $("#loader").css("display", "none");
            $("#responsePrint").css("display", "");
        }
    }
}

function toggleData() {
    if(jQuery.inArray($(':selected').val(), ["post", "put"]) > -1) {
        $("#data").css("display", "");
        $("#postputaction").css("display", "");
    } else {
        $("#data").css("display", "none");
        $("#postputaction").css("display", "none");
    }
}

function resizeFields(){
    $("#url").width($("#purl").width()-250);
    $("#headers").width($("#pheaders").width()-250);
    $("#postputdata").width($("#data").width()-250);

    $("#responseHeaders").width($("#respHeaders").width()-110);
    $("#responseData").width($("#respHeaders").width()-110);
}

function init() {
    resizeFields();
    $("#response").css("display", "none");
    $("#loader").css("display", "");
    $("#responsePrint").css("display", "none");

    $("#data").css("display", "none");
    $("#postputaction").css("display", "none");

    $("#responseStatus").html("");
    $("#respHeaders").css("display", "none");
    $("#respData").css("display", "none");
    
    loadLastQuery();

    $("#submit").click(function() {
        sendRequest();
        return false;
    });
    $("#reset").click(function() {
        clearLastQuery();
        location.reload();
    });
    $(".select").change(function() {
        toggleData();
    });
    $(".select").focus(function() {
        toggleData();
    });
}

function lang() {
    return;
    $('._msg_').each(function () {
        var val = $(this).html();
        $(this).html(chrome.i18n.getMessage(val));
    });
    $('._msg_val_').each(function () {
        var val = $(this).val();
        $(this).val(chrome.i18n.getMessage(val));
    });
}

$(document).ready(function() {
    //go full screen on click
    $('.codeDataFullscreen').click(function() {
        $("#container").css("display", "none");
        $("#fullscreen").css("display", "block");
    });
    
    //close fullscreen on click
    $('#fullscreenClose').click(function() {
        $("#container").css("display", "");
        $("#fullscreen").css("display", "none");
    });
    
    //if the window size change
    window.onresize = function(){
        resizeFields();
        $("#fullscreen").width(window.innerWidth-20);
        $("#fullscreen").height(window.innerHeight-20);
        $("#fullscreenClose").css("left",window.innerWidth-60+"px");
    }
    
    //lang();
    init();
});



/* Jison generated parser */
var jsonlint = (function(){
    var parser = {
        trace: function trace() { },
        yy: {},
        symbols_: {
            "error":2,
            "JSONString":3,
            "STRING":4,
            "JSONNumber":5,
            "NUMBER":6,
            "JSONNullLiteral":7,
            "NULL":8,
            "JSONBooleanLiteral":9,
            "TRUE":10,
            "FALSE":11,
            "JSONText":12,
            "JSONValue":13,
            "EOF":14,
            "JSONObject":15,
            "JSONArray":16,
            "{":17,
            "}":18,
            "JSONMemberList":19,
            "JSONMember":20,
            ":":21,
            ",":22,
            "[":23,
            "]":24,
            "JSONElementList":25,
            "$accept":0,
            "$end":1
        },
        terminals_: {
            2:"error",
            4:"STRING",
            6:"NUMBER",
            8:"NULL",
            10:"TRUE",
            11:"FALSE",
            14:"EOF",
            17:"{",
            18:"}",
            21:":",
            22:",",
            23:"[",
            24:"]"
        },
        productions_: [0,[3,1],[5,1],[7,1],[9,1],[9,1],[12,2],[13,1],[13,1],[13,1],[13,1],[13,1],[13,1],[15,2],[15,3],[20,3],[19,1],[19,3],[16,2],[16,3],[25,1],[25,3]],
        performAction: function anonymous(yytext,yyleng,yylineno,yy,yystate,$$,_$) {

            var $0 = $$.length - 1;
            switch (yystate) {
                case 1:
                    this.$ = yytext;
                    break;
                case 2:
                    this.$ = Number(yytext);
                    break;
                case 3:
                    this.$ = null;
                    break;
                case 4:
                    this.$ = true;
                    break;
                case 5:
                    this.$ = false;
                    break;
                case 6:
                    return this.$ = $$[$0-1];
                    break;
                case 13:
                    this.$ = {};
                    break;
                case 14:
                    this.$ = $$[$0-1];
                    break;
                case 15:
                    this.$ = [$$[$0-2], $$[$0]];
                    break;
                case 16:
                    this.$ = {};                    
                    this.$[$$[$0][0]] = $$[$0][1];
                    break;
                case 17:
                    this.$ = $$[$0-2];
                    $$[$0-2][$$[$0][0]] = $$[$0][1];
                    break;
                case 18:
                    this.$ = [];
                    break;
                case 19:
                    this.$ = $$[$0-1];
                    break;
                case 20:
                    this.$ = [$$[$0]];
                    break;
                case 21:
                    this.$ = $$[$0-2];
                    $$[$0-2].push($$[$0]);
                    break;
            }
        },
        table: [{
            3:5,
            4:[1,12],
            5:6,
            6:[1,13],
            7:3,
            8:[1,9],
            9:4,
            10:[1,10],
            11:[1,11],
            12:1,
            13:2,
            15:7,
            16:8,
            17:[1,14],
            23:[1,15]
        },{
            1:[3]
        },{
            14:[1,16]
        },{
            14:[2,7],
            18:[2,7],
            22:[2,7],
            24:[2,7]
        },{
            14:[2,8],
            18:[2,8],
            22:[2,8],
            24:[2,8]
        },{
            14:[2,9],
            18:[2,9],
            22:[2,9],
            24:[2,9]
        },{
            14:[2,10],
            18:[2,10],
            22:[2,10],
            24:[2,10]
        },{
            14:[2,11],
            18:[2,11],
            22:[2,11],
            24:[2,11]
        },{
            14:[2,12],
            18:[2,12],
            22:[2,12],
            24:[2,12]
        },{
            14:[2,3],
            18:[2,3],
            22:[2,3],
            24:[2,3]
        },{
            14:[2,4],
            18:[2,4],
            22:[2,4],
            24:[2,4]
        },{
            14:[2,5],
            18:[2,5],
            22:[2,5],
            24:[2,5]
        },{
            14:[2,1],
            18:[2,1],
            21:[2,1],
            22:[2,1],
            24:[2,1]
        },{
            14:[2,2],
            18:[2,2],
            22:[2,2],
            24:[2,2]
        },{
            3:20,
            4:[1,12],
            18:[1,17],
            19:18,
            20:19
        },{
            3:5,
            4:[1,12],
            5:6,
            6:[1,13],
            7:3,
            8:[1,9],
            9:4,
            10:[1,10],
            11:[1,11],
            13:23,
            15:7,
            16:8,
            17:[1,14],
            23:[1,15],
            24:[1,21],
            25:22
        },{
            1:[2,6]
        },{
            14:[2,13],
            18:[2,13],
            22:[2,13],
            24:[2,13]
        },{
            18:[1,24],
            22:[1,25]
        },{
            18:[2,16],
            22:[2,16]
        },{
            21:[1,26]
        },{
            14:[2,18],
            18:[2,18],
            22:[2,18],
            24:[2,18]
        },{
            22:[1,28],
            24:[1,27]
        },{
            22:[2,20],
            24:[2,20]
        },{
            14:[2,14],
            18:[2,14],
            22:[2,14],
            24:[2,14]
        },{
            3:20,
            4:[1,12],
            20:29
        },{
            3:5,
            4:[1,12],
            5:6,
            6:[1,13],
            7:3,
            8:[1,9],
            9:4,
            10:[1,10],
            11:[1,11],
            13:30,
            15:7,
            16:8,
            17:[1,14],
            23:[1,15]
        },{
            14:[2,19],
            18:[2,19],
            22:[2,19],
            24:[2,19]
        },{
            3:5,
            4:[1,12],
            5:6,
            6:[1,13],
            7:3,
            8:[1,9],
            9:4,
            10:[1,10],
            11:[1,11],
            13:31,
            15:7,
            16:8,
            17:[1,14],
            23:[1,15]
        },{
            18:[2,17],
            22:[2,17]
        },{
            18:[2,15],
            22:[2,15]
        },{
            22:[2,21],
            24:[2,21]
        }],
        defaultActions: {
            16:[2,6]
        },
        parseError: function parseError(str, hash) {
            throw new Error(str);
        },
        parse: function parse(input) {
            var self = this,
            stack = [0],
            vstack = [null], // semantic value stack
            lstack = [], // location stack
            table = this.table,
            yytext = '',
            yylineno = 0,
            yyleng = 0,
            recovering = 0,
            TERROR = 2,
            EOF = 1;

            // this.reductionCount = this.shiftCount = 0;

            this.lexer.setInput(input);
            this.lexer.yy = this.yy;
            this.yy.lexer = this.lexer;
            if (typeof this.lexer.yylloc == 'undefined')
                this.lexer.yylloc = {};
            var yyloc = this.lexer.yylloc;
            lstack.push(yyloc);

            if (typeof this.yy.parseError === 'function')
                this.parseError = this.yy.parseError;

            function popStack (n) {
                stack.length = stack.length - 2*n;
                vstack.length = vstack.length - n;
                lstack.length = lstack.length - n;
            }

            function lex() {
                var token;
                token = self.lexer.lex() || 1; // $end = 1
                // if token isn't its numeric value, convert
                if (typeof token !== 'number') {
                    token = self.symbols_[token] || token;
                }
                return token;
            };

            var symbol, preErrorSymbol, state, action, a, r, yyval={},p,len,newState, expected;
            while (true) {
                // retreive state number from top of stack
                state = stack[stack.length-1];

                // use default actions if available
                if (this.defaultActions[state]) {
                    action = this.defaultActions[state];
                } else {
                    if (symbol == null)
                        symbol = lex();
                    // read action for current state and first input
                    action = table[state] && table[state][symbol];
                }

                // handle parse error
                if (typeof action === 'undefined' || !action.length || !action[0]) {

                    if (!recovering) {
                        // Report error
                        expected = [];
                        for (p in table[state]) if (this.terminals_[p] && p > 2) {
                            expected.push("'"+this.terminals_[p]+"'");
                        }
                        var errStr = '';
                        if (this.lexer.showPosition) {
                            errStr = 'Parse error on line '+(yylineno+1)+":\n"+this.lexer.showPosition()+'\nExpecting '+expected.join(', ');
                        } else {
                            errStr = 'Parse error on line '+(yylineno+1)+": Unexpected " +
                            (symbol == 1 /* EOF */ ? "end of input" :
                                ("'"+(this.terminals_[symbol] || symbol)+"'"));
                        }
                        this.parseError(errStr,
                        {
                            text: this.lexer.match, 
                            token: this.terminals_[symbol] || symbol, 
                            line: this.lexer.yylineno, 
                            loc: yyloc, 
                            expected: expected
                        });
                    }

                    // just recovered from another error
                    if (recovering == 3) {
                        if (symbol == EOF) {
                            throw new Error(errStr || 'Parsing halted.');
                        }

                        // discard current lookahead and grab another
                        yyleng = this.lexer.yyleng;
                        yytext = this.lexer.yytext;
                        yylineno = this.lexer.yylineno;
                        yyloc = this.lexer.yylloc;
                        symbol = lex();
                    }

                    // try to recover from error
                    while (1) {
                        // check for error recovery rule in this state
                        if ((TERROR.toString()) in table[state]) {
                            break;
                        }
                        if (state == 0) {
                            throw new Error(errStr || 'Parsing halted.');
                        }
                        popStack(1);
                        state = stack[stack.length-1];
                    }

                    preErrorSymbol = symbol; // save the lookahead token
                    symbol = TERROR;         // insert generic error symbol as new lookahead
                    state = stack[stack.length-1];
                    action = table[state] && table[state][TERROR];
                    recovering = 3; // allow 3 real symbols to be shifted before reporting a new error
                }

                // this shouldn't happen, unless resolve defaults are off
                if (action[0] instanceof Array && action.length > 1) {
                    throw new Error('Parse Error: multiple actions possible at state: '+state+', token: '+symbol);
                }

                switch (action[0]) {

                    case 1: // shift
                        // this.shiftCount++;

                        stack.push(symbol);
                        vstack.push(this.lexer.yytext);
                        lstack.push(this.lexer.yylloc);
                        stack.push(action[1]); // push state
                        symbol = null;
                        if (!preErrorSymbol) { // normal execution/no error
                            yyleng = this.lexer.yyleng;
                            yytext = this.lexer.yytext;
                            yylineno = this.lexer.yylineno;
                            yyloc = this.lexer.yylloc;
                            if (recovering > 0)
                                recovering--;
                        } else { // error just occurred, resume old lookahead f/ before error
                            symbol = preErrorSymbol;
                            preErrorSymbol = null;
                        }
                        break;

                    case 2: // reduce
                        // this.reductionCount++;

                        len = this.productions_[action[1]][1];

                        // perform semantic action
                        yyval.$ = vstack[vstack.length-len]; // default to $$ = $1
                        // default location, uses first token for firsts, last for lasts
                        yyval._$ = {
                            first_line: lstack[lstack.length-(len||1)].first_line,
                            last_line: lstack[lstack.length-1].last_line,
                            first_column: lstack[lstack.length-(len||1)].first_column,
                            last_column: lstack[lstack.length-1].last_column
                        };
                        r = this.performAction.call(yyval, yytext, yyleng, yylineno, this.yy, action[1], vstack, lstack);

                        if (typeof r !== 'undefined') {
                            return r;
                        }

                        // pop off stack
                        if (len) {
                            stack = stack.slice(0,-1*len*2);
                            vstack = vstack.slice(0, -1*len);
                            lstack = lstack.slice(0, -1*len);
                        }

                        stack.push(this.productions_[action[1]][0]);    // push nonterminal (reduce)
                        vstack.push(yyval.$);
                        lstack.push(yyval._$);
                        // goto new state = table[STATE][NONTERMINAL]
                        newState = table[stack[stack.length-2]][stack[stack.length-1]];
                        stack.push(newState);
                        break;

                    case 3: // accept
                        return true;
                }

            }

            return true;
        }
    };/* Jison generated lexer */
    var lexer = (function(){
        var lexer = ({
            EOF:1,
            parseError:function parseError(str, hash) {
                if (this.yy.parseError) {
                    this.yy.parseError(str, hash);
                } else {
                    throw new Error(str);
                }
            },
            setInput:function (input) {
                this._input = input;
                this._more = this._less = this.done = false;
                this.yylineno = this.yyleng = 0;
                this.yytext = this.matched = this.match = '';
                this.conditionStack = ['INITIAL'];
                this.yylloc = {
                    first_line:1,
                    first_column:0,
                    last_line:1,
                    last_column:0
                };
                return this;
            },
            input:function () {
                var ch = this._input[0];
                this.yytext+=ch;
                this.yyleng++;
                this.match+=ch;
                this.matched+=ch;
                var lines = ch.match(/\n/);
                if (lines) this.yylineno++;
                this._input = this._input.slice(1);
                return ch;
            },
            unput:function (ch) {
                this._input = ch + this._input;
                return this;
            },
            more:function () {
                this._more = true;
                return this;
            },
            pastInput:function () {
                var past = this.matched.substr(0, this.matched.length - this.match.length);
                return (past.length > 20 ? '...':'') + past.substr(-20).replace(/\n/g, "");
            },
            upcomingInput:function () {
                var next = this.match;
                if (next.length < 20) {
                    next += this._input.substr(0, 20-next.length);
                }
                return (next.substr(0,20)+(next.length > 20 ? '...':'')).replace(/\n/g, "");
            },
            showPosition:function () {
                var pre = this.pastInput();
                var c = new Array(pre.length + 1).join("-");
                return pre + this.upcomingInput() + "\n" + c+"^";
            },
            next:function () {
                if (this.done) {
                    return this.EOF;
                }
                if (!this._input) this.done = true;

                var token,
                match,
                col,
                lines;
                if (!this._more) {
                    this.yytext = '';
                    this.match = '';
                }
                var rules = this._currentRules();
                for (var i=0;i < rules.length; i++) {
                    match = this._input.match(this.rules[rules[i]]);
                    if (match) {
                        lines = match[0].match(/\n.*/g);
                        if (lines) this.yylineno += lines.length;
                        this.yylloc = {
                            first_line: this.yylloc.last_line,
                            last_line: this.yylineno+1,
                            first_column: this.yylloc.last_column,
                            last_column: lines ? lines[lines.length-1].length-1 : this.yylloc.last_column + match[0].length
                        }
                        this.yytext += match[0];
                        this.match += match[0];
                        this.matches = match;
                        this.yyleng = this.yytext.length;
                        this._more = false;
                        this._input = this._input.slice(match[0].length);
                        this.matched += match[0];
                        token = this.performAction.call(this, this.yy, this, rules[i],this.conditionStack[this.conditionStack.length-1]);
                        if (token) return token;
                        else return;
                    }
                }
                if (this._input === "") {
                    return this.EOF;
                } else {
                    this.parseError('Lexical error on line '+(this.yylineno+1)+'. Unrecognized text.\n'+this.showPosition(), 
                    {
                        text: "", 
                        token: null, 
                        line: this.yylineno
                    });
                }
            },
            lex:function lex() {
                var r = this.next();
                if (typeof r !== 'undefined') {
                    return r;
                } else {
                    return this.lex();
                }
            },
            begin:function begin(condition) {
                this.conditionStack.push(condition);
            },
            popState:function popState() {
                return this.conditionStack.pop();
            },
            _currentRules:function _currentRules() {
                return this.conditions[this.conditionStack[this.conditionStack.length-1]].rules;
            }
        });
        lexer.performAction = function anonymous(yy,yy_,$avoiding_name_collisions,YY_START) {

            var YYSTATE=YY_START
            switch($avoiding_name_collisions) {
                case 0:/* skip whitespace */
                    break;
                case 1:
                    return 6;
                    break;
                case 2:
                    yy_.yytext = yy_.yytext.substr(1,yy_.yyleng-2);
                    return 4;
                    break;
                case 3:
                    return 17 
                    break;
                case 4:
                    return 18 
                    break;
                case 5:
                    return 23
                    break;
                case 6:
                    return 24
                    break;
                case 7:
                    return 22
                    break;
                case 8:
                    return 21
                    break;
                case 9:
                    return 10
                    break;
                case 10:
                    return 11
                    break;
                case 11:
                    return 8
                    break;
                case 12:
                    return 14
                    break;
                case 13:
                    return 'INVALID'
                    break;
            }
        };
        lexer.rules = [/^\s+/,/^-?([0-9]|[1-9][0-9]+)(\.[0-9]+)?([eE][-+]?[0-9]+)?\b/,/^"(\\["bfnrt/\\]|\\u[a-fA-F0-9]{4}|[^\0-\x09\x0a-\x1f"\\])*"/,/^\{/,/^\}/,/^\[/,/^\]/,/^,/,/^:/,/^true\b/,/^false\b/,/^null\b/,/^$/,/^./];
        lexer.conditions = {
            "INITIAL":{
                "rules":[0,1,2,3,4,5,6,7,8,9,10,11,12,13],
                "inclusive":true
            }
        };

        return lexer;
    })()
    parser.lexer = lexer;
    return parser;
})();
if (typeof require !== 'undefined' && typeof exports !== 'undefined') {
    exports.parser = jsonlint;
    exports.parse = function () {
        return jsonlint.parse.apply(jsonlint, arguments);
    }
    exports.main = function commonjsMain(args) {
        if (!args[1])
            throw new Error('Usage: '+args[0]+' FILE');
        if (typeof process !== 'undefined') {
            var source = require('fs').readFileSync(require('path').join(process.cwd(), args[1]), "utf8");
        } else {
            var cwd = require("file").path(require("file").cwd());
            var source = cwd.join(args[1]).read({
                charset: "utf-8"
            });
        }
        return exports.parser.parse(source);
    }
    if (typeof module !== 'undefined' && require.main === module) {
        exports.main(typeof process !== 'undefined' ? process.argv.slice(1) : require("system").args);
    }
}
        
        
        
        
        
/*JSON FORMATTER*/
function JSONFormatter() {
}
JSONFormatter.prototype = {
    htmlEncode : function(t) {
        return t != null ? t.toString().replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;") : '';
    },

    decorateWithSpan : function(value, className) {
        return '<span class="' + className + '">' + this.htmlEncode(value) + '</span>';
    },

    valueToHTML : function(value) {
        var valueType = typeof value, output = "";
        if (value == null) {
            output += this.decorateWithSpan('null', 'null');
        } else if (value && value.constructor == Array) {
            output += this.arrayToHTML(value);
        } else if (valueType == 'object') {
            output += this.objectToHTML(value);
        } else if (valueType == 'number') {
            output += this.decorateWithSpan(value, 'num');
        } else if (valueType == 'string') {
            if (/^(http|https):\/\/[^\s]+$/.test(value)) {
                output += this.decorateWithSpan('"', 'string') + '<a href="' + value + '">' + this.htmlEncode(value) + '</a>'
                + this.decorateWithSpan('"', 'string');
            } else {
                output += this.decorateWithSpan('"' + value + '"', 'string');
            }
        } else if (valueType == 'boolean') {
            output += this.decorateWithSpan(value, 'bool');
        }

        return output;
    },

    arrayToHTML : function(json) {
        var prop, output = '[<ul class="array collapsible">', hasContents = false;
        for (prop in json) {
            hasContents = true;
            output += '<li>';
            output += this.valueToHTML(json[prop]);
            output += '</li>';
        }
        output += '</ul>]';

        if (!hasContents) {
            output = "[ ]";
        }

        return output;
    },

    objectToHTML : function(json) {
        var prop, output = '{<ul class="obj collapsible">', hasContents = false;
        for (prop in json) {
            hasContents = true;
            output += '<li>';
            output += '<span class="prop">' + this.htmlEncode(prop) + '</span>: ';
            output += this.valueToHTML(json[prop]);
            output += '</li>';
        }
        output += '</ul>}';

        if (!hasContents) {
            output = "{ }";
        }

        return output;
    },

    jsonToHTML : function(json, fnName) {
        var output = '';
        if (fnName)
            output += '<div class="fn">' + fnName + '(</div>';
        output += '<div id="json">';
        output += this.valueToHTML(json);
        output += '</div>';
        if (fnName)
            output += '<div class="fn">)</div>';
        return output;
    }
};

/**
         * Click handler for collapsing and expanding objects and arrays
         * 
         * @param {Event} evt
         */
function collapse(evt) {
    var ellipsis, collapser = evt.target, target = collapser.parentNode.getElementsByClassName('collapsible')[0];
    if (!target)
        return;

    if (target.style.display == 'none') {
        ellipsis = target.parentNode.getElementsByClassName('ellipsis')[0];
        target.parentNode.removeChild(ellipsis);
        target.style.display = '';
    } else {
        target.style.display = 'none';
        ellipsis = document.createElement('span');
        ellipsis.className = 'ellipsis';
        ellipsis.innerHTML = ' &hellip; ';
        target.parentNode.insertBefore(ellipsis, target);
    }
    collapser.innerHTML = (collapser.innerHTML == '-') ? '+' : '-';
}

function displayObject(jsonText, fnName) {
    var parsedObject, errorBox, closeBox;
    if (!jsonText)
        return;
    try {
        parsedObject = JSON.parse(jsonText);
    } catch (e) {
    }
    document.body.style.fontFamily = "monospace"; // chrome bug : does not work in external CSS stylesheet
    if (!parsedObject) {
        try {
            jsonlint.parse(jsonText);
        } catch (e) {
            document.body.innerHTML += '<link rel="stylesheet" type="text/css" href="' + chrome.extension.getURL("content_error.css") + '">';
            errorBox = document.createElement("pre");
            closeBox = document.createElement("div");
            errorBox.className = "error";
            closeBox.className = "close-error";
            closeBox.onclick = function() {
                errorBox.parentElement.removeChild(errorBox);
            };
            errorBox.textContent = e;
            errorBox.appendChild(closeBox);
            setTimeout(function() {
                document.body.appendChild(errorBox);
                errorBox.style.pixelLeft = Math.max(0, Math.floor((window.innerWidth - errorBox.offsetWidth) / 2));
                errorBox.style.pixelTop = Math.max(0, Math.floor((window.innerHeight - errorBox.offsetHeight) / 2));
            }, 100);
        }
        return;
    }
    //document.body.innerHTML = '<link rel="stylesheet" type="text/css" href="' + chrome.extension.getURL("content.css") + '">'
    + new JSONFormatter().jsonToHTML(parsedObject, fnName);
    Array.prototype.forEach.call(document.getElementsByClassName('collapsible'), function(childItem) {
        var collapser, item = childItem.parentNode;
        if (item.nodeName == 'LI') {
            collapser = document.createElement('div');
            collapser.className = 'collapser';
            collapser.innerHTML = '-';
            collapser.addEventListener('click', collapse, false);
            item.insertBefore(collapser, item.firstChild);
        }
    });
}

function extractData(text) {
    var tokens;
    if ((text.charAt(0) == "{" || text.charAt(0) == "[") && (text.charAt(text.length - 1) == "}" || text.charAt(text.length - 1) == "]"))
        return {
            text : text
        };
    tokens = text.match(/^([^\s\(]*)\s*\(\s*([\[{].*[\]}])\s*\)(?:\s*;?)*\s*$/);
    if (tokens && tokens[1] && tokens[2])
        return {
            fnName : tokens[1],
            text : tokens[2]
        };
}

function processData(data, options) {
    var xhr;
    if (options.safeMethod) {
        xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {
            if (this.readyState == 4) {
                data = extractData(this.responseText);
                if (data)
                    displayObject(data.text, data.fnName);
            }
        };
        xhr.open("GET", document.location.href, true);
        xhr.send(null);
    } else if (data)
        displayObject(data.text, data.fnName);
}

function init1(data) {
    var port = chrome.extension.connect();
    port.onMessage.addListener(function(msg) {
        if (msg.init)
            processData(data, msg.options);
    });
    port.postMessage({
        init : true
    });
}

function load() {
    var child, data;
    if (document.body && document.body.childNodes[0] && document.body.childNodes[0].tagName == "PRE" || document.body.children.length == 0) {
        child = document.body.children.length ? document.body.childNodes[0] : document.body;
        data = extractData(child.innerText.trim());
        if (data)
            init(data);
    }
}
        
function isValidJson(json){
    var value = false;
    try
    {
        jsonObject = jsonlint.parse(json);
        var tmpJson = JSON.stringify(jsonObject, null, "  ");
        var parsedObject = JSON.parse(tmpJson);
        value = new JSONFormatter().objectToHTML(parsedObject);
    }
    catch(err)
    {
        value = false;
    }
    return value;
}