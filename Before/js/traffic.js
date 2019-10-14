var pos_xmlhttp;

function sushi_random()
{
    var rn;

    rn = Math.floor(Math.random()*100001);
    return '&randn='+rn;
}


function requestObject()
{
  var xmlhttp;
  if (window.XMLHttpRequest)
  {
    // code for IE7+, Firefox, Chrome, Opera, Safari
    xmlhttp=new XMLHttpRequest();
  } else
  {
    // code for IE6, IE5
    xmlhttp=new ActiveXObject("Microsoft.XMLHTTP");
  }

  return xmlhttp;
}

function sushi_process_common(type, aa)
{
    if (type == 'redirect')
    {
      var where = aa.getElementsByTagName('where')[0].childNodes[0].nodeValue;
      where = where.replace(/\%26/g,'&');
      window.location.href = where;

    } else if (type == 'refill')
    {
      var where = aa.getElementsByTagName('where')[0].childNodes[0].nodeValue;
      var what  = aa.getElementsByTagName('what')[0].childNodes[0].nodeValue;
      var where_html = document.getElementById(where);

      if (where_html != null)
      {
        where_html.innerHTML = sushi64(what);
      }

    } else if (type == 'append')
    {
      var where = aa.getElementsByTagName('where')[0].childNodes[0].nodeValue;
      var what  = aa.getElementsByTagName('what')[0].childNodes[0].nodeValue;
      var where_html = document.getElementById(where);

      if (where_html != null)
      {
        where_html.innerHTML = where_html.innerHTML + sushi64(what);
      }

    }
}

function sushi64(input)
{
  var key = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  var output = "";
  var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
  var i = 0;

  input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

  while (i < input.length)
  {
    enc1 = key.indexOf(input.charAt(i++));
    enc2 = key.indexOf(input.charAt(i++));
    enc3 = key.indexOf(input.charAt(i++));
    enc4 = key.indexOf(input.charAt(i++));

    chr1 =  (enc1 << 2)       | (enc2 >> 4);
    chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
    chr3 = ((enc3 & 3) << 6)  |  enc4;

    output = output + String.fromCharCode(chr1);

    if (enc3 != 64)
    {
      output = output + String.fromCharCode(chr2);
    }

    if (enc4 != 64)
    {
      output = output + String.fromCharCode(chr3);
    }
  }

  return output;
}



function sushi64p(input)
{
  var key = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  var output = [];
  var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
  var i = 0;
  var pos = 0;

  var el,al;

  input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

  el = 0;
 
  while (i < input.length)
  {
    enc1 = key.indexOf(input.charAt(i++));
    enc2 = key.indexOf(input.charAt(i++));
    enc3 = key.indexOf(input.charAt(i++));
    enc4 = key.indexOf(input.charAt(i++));
 
    chr1 =  (enc1 << 2)       | (enc2 >> 4);
    chr2 = ((enc2 & 15) << 4) | ((enc3 & 15)>> 2);
    chr3 = ((enc3 & 3) << 6)  |  (enc4 & 63);
 
    output[pos] = chr1; pos += 1;
    el += 1;
 
    if (enc3 != 64)
    {
      output[pos] = chr2; pos += 1;
      el += 1;
    }

    if (enc4 != 64)
    {
      output[pos] = chr3; pos += 1;
      el += 1;
    }
  }
  
  ml = output.length;

  return output;
}


function pos_response()
{
  var content;
  var res;
  var e;

  if (pos_xmlhttp.readyState == 4)
  {
    res = pos_xmlhttp.responseXML;



    res.normalize();

    pos_process_extend(res);

    e = document.getElementById('ins');


    if (e != null)
    {
      pos_local_clr();
      pos_refresh();
    }
  }
}

function pos_response_norefresh()
{
  var content;
  var res;
  var e;

  if (pos_xmlhttp.readyState == 4)
  {
    res = pos_xmlhttp.responseXML;

    res.normalize();

    pos_process_extend(res);

    e = document.getElementById('ins');


    if (e != null)
    {
      pos_local_clr();
    }
  }
}

function pos_process_extend(response)
{
  var aa;

  aa = response.getElementsByTagName('action');

  for(var i = 0, len = aa.length; i < len; i += 1)
  {
    var type = aa[i].getElementsByTagName('type')[0].childNodes[0].nodeValue;

    if (type == 'total')
    {
      var total = aa[i].getElementsByTagName('value')[0].childNodes[0].nodeValue;
      setTotal = total;

    } else if (type == 'highlight')
    {
      var id = aa[i].getElementsByTagName('iid')[0].childNodes[0].nodeValue;
      var e = document.getElementById(id);
      e.style.background='#ff0';

    } else if (type == 'lowlight')
    {
      var id = aa[i].getElementsByTagName('iid')[0].childNodes[0].nodeValue;
      var e = document.getElementById(id);
      e.style.background='#eee';

    } else if (type == 'reset')
    {
	setReset = 1;

    } else
    {
      sushi_process_common(type, aa[i]);
    }
  }
}

function pos_refresh()
{
    var e,t,s;
    var x, h;
    s = document.getElementById('lstate1');

    h='';

    if (setRefund == 4)
    {
	h='Refund ';
    }

    if (setNum != 1)
    {
	h = h+'x '+setNum;
    }

    if (h == '')
    {
	h = '&nbsp;';
    }

    s.innerHTML = h;

    s = document.getElementById('lstate2');

    if (setShiftId != 0)
    {
      s.innerHTML = setShiftLabel;
    } else
    {
      s.innerHTML = '&nbsp;';
    }


    s = document.getElementById('rstate2');

    if (setTotal < 0)
    {
      s.innerHTML = 'Total -&pound;'+Number(setTotal/-100).toFixed(2);
    } else
    {
      s.innerHTML = 'Total &pound;'+Number(setTotal/100).toFixed(2);
    }

    e = document.getElementById('ins');
    t = document.getElementById('target');
    t.scrollTop = t.scrollHeight;
    e.focus();
}

function get_radio_value(radio)
{
  var rs = document.getElementsByName(radio);

  for (var i = 0, length = rs.length; i < length; i++)
  {
    if (rs[i].checked)
    {
      return rs[i].value;
    }
  }
  return '';
}

// action commands

encodeURIComponent

function command_login()
{

    username = encodeURIComponent(document.getElementById('ofUser').value);
    password = encodeURIComponent(document.getElementById('ofPassword').value);

    pos_xmlhttp = requestObject();
    pos_xmlhttp.onreadystatechange=pos_response;
    pos_xmlhttp.open('GET','/action?command=login&usernameinput='+username+'&passwordinput='+password+sushi_random(),true);
    pos_xmlhttp.send(null);
}

function command_add()
{
    loc = encodeURIComponent(document.getElementById('ofLocation').value);
    type = encodeURIComponent(get_radio_value('ofType'));
    occupancy = encodeURIComponent(get_radio_value('ofOccupancy'));

    pos_xmlhttp = requestObject();
    pos_xmlhttp.onreadystatechange=pos_response;
    pos_xmlhttp.open('GET','/action?command=add&locationinput='+loc+'&occupancyinput='+occupancy+'&typeinput='+type+sushi_random(),true);
    pos_xmlhttp.send(null);
}

function command_undo()
{

    loc = encodeURIComponent(document.getElementById('ofLocation').value);
    type = encodeURIComponent(get_radio_value('ofType'));
    occupancy = encodeURIComponent(get_radio_value('ofOccupancy'));

    pos_xmlhttp = requestObject();
    pos_xmlhttp.onreadystatechange=pos_response;
    pos_xmlhttp.open('GET','/action?command=undo&locationinput='+loc+'&occupancyinput='+occupancy+'&typeinput='+type+sushi_random(),true);
    pos_xmlhttp.send(null);
}

function command_back()
{
    pos_xmlhttp = requestObject();
    pos_xmlhttp.onreadystatechange=pos_response;
    pos_xmlhttp.open('GET','/action?command=back'+sushi_random(),true);
    pos_xmlhttp.send(null);
}

function command_summary()
{
    pos_xmlhttp = requestObject();
    pos_xmlhttp.onreadystatechange=pos_response;
    pos_xmlhttp.open('GET','/action?command=summary'+sushi_random(),true);
    pos_xmlhttp.send(null);
}

function command_logout()
{
    pos_xmlhttp = requestObject();
    pos_xmlhttp.onreadystatechange=pos_response;
    pos_xmlhttp.open('GET','/action?command=logout'+sushi_random(),true);
    pos_xmlhttp.send(null);
}

