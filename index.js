/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const 
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),  
  request = require('request');

var app = express();

 //facebook sdk for get user inforamtion.
  var sdk = require('facebook-node-sdk');
        var fb = new sdk({
            appId: config.get('AppId'),
            secret: config.get('appSecret')
        }).setAccessToken(config.get('pageAccessToken'));

app.set('port', process.env.PORT || 5000);
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

/*
 * Be sure to setup your config values before running this code. You can 
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ? 
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN)) {
  console.error("Missing config values");
  process.exit(1);
}

app.get('/', function(req, res) {
 res.send('Welcome to Facebook Store Audit  Bot...!'); 
});
/*
 * Use your own validation token. Check that the token used in the Webhook 
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);          
  }  
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page. 
 * https://developers.facebook.com/docs/messenger-platform/implementation#subscribe_app_pages
 *
 */
app.post('/webhook', function (req, res) {

  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've 
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from 
 * the App Dashboard, we can verify the signature that is sent with each 
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an 
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to 
 * Messenger" plugin, it is the 'data-ref' field. Read more at 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference#auth
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the 
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger' 
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam, 
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}


/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message' 
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference#received_message
 *
 * For this example, we're going to echo any text that we get. If we get some 
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've 
 * created. If we receive a message with an attachment (image, video, audio), 
 * then we'll simply confirm that we've received the attachment.
 * 
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  var messageId = message.mid;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;


  if (messageText) {
 // console.log("before text");
  checkstatus(senderID,messageText,"text","");
   //console.log("after text");
    // If we receive a text message, check to see if it matches any special
    // keywords and send back the corresponding example. Otherwise, just echo
    // the text we received.
//    switch (messageText) {  
//      case 'receipt':
//        sendReceiptMessage(senderID);
//        break;
//      default:
//        sendTextMessage(senderID, messageText);
//    }
  } else if (messageAttachments) {
 
   checkstatus(senderID,"file",messageAttachments[0].type,messageAttachments);
   // sendTextMessage(senderID, "Message with attachment received");

  }
}


/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about 
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference#message_delivery
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;               

  if (messageIDs) {
//    messageIDs.forEach(function(messageID) {
//      console.log("Received delivery confirmation for message ID: %s", 
//        messageID);

//           
//    });
  }

  //console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message. Read
 * more at https://developers.facebook.com/docs/messenger-platform/webhook-reference#postback
 * 
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback 
  // button for Structured Messages. 
  var payload = event.postback.payload;
  console.log(payload);
  if(payload=="Q1YES")
  { 

             fb.api('/' + senderID + '', function (err, data) {            
                     if (data) {                    
                     assignmission(senderID,data.first_name+" "+data.last_name,data.profile_pic,"Q1YES");   
                     }
                     }); 

      var messageData = {
        "attachment": {
            "type": "template",
            "payload": {
                "template_type": "generic",
                "elements": [{
                    "title": "Do you have invoices for soft drinks purchased today?",
                    "subtitle": "",
                    "buttons": [{
                        "type": "postback",
                        "title": "Yes",
                        "payload": "Q2YES"
                    }, {
                        "type": "postback",
                        "title": "No",
                        "payload": "Q2NO"
                    }]
                }]
            }
        }
    };
      sendGenericMessage(senderID,messageData);  
  }
  else if(payload=="Q1NO")
  {
   fb.api('/' + senderID + '', function (err, data) {            
                     if (data) {                    
                     assignmission(senderID,data.first_name+" "+data.last_name,data.profile_pic,"Q1NO");   
                     }
                     }); 
  sendTextMessage(senderID,"Thank You");
  }
  else if(payload=="Q2YES")
  {
   SendQ2status(senderID,"Q2YES");
  sendTextMessage(senderID,"Please use the camera button below to take a photo of the invoice and send it to me.");
  }
  else if(payload=="Q2NO"){ 
  SendQ2status(senderID,"Q2NO");  
  sendTextMessage(senderID,"How many unique soft drink items you purchased today for which you do not have the invoice?");
  sendTextMessage(senderID,"Please provide the number of unique items (SKU) you purchased today having different Brand/Pack size/Pack type? (Example: 2 Items purchased - if you purchased Coke 200 ML Plastic and Coke 100 ML Glass)");
  }
  else if(payload=="Q4NO")
  {
  checkstatus(senderID,"Q4NO","text","");
  }
   else if(payload=="Q4YES")
  {
   checkstatus(senderID,"Q4YES","text","");
  }
  else if(payload=="MOREITEMSYES")
  {
  checkstatus(senderID,"MOREITEMSYES","text","");
  }
  else if(payload=="MOREITEMSNO")
  {
  checkstatus(senderID,"MOREITEMSNO","text","");
  }
  else if(payload=="FINALCONFIRMYES")
  {
  checkstatus(senderID,"FINALCONFIRMYES","text","");
  }
  else if(payload=="FINALCONFIRMNO")
  {
  checkstatus(senderID,"FINALCONFIRMNO","text","");
  }

  // When a postback is called, we'll send a message back to the sender to 
  // let them know it was successful

}


/*
 * Send a message with an using the Send API.
 *
 */
function sendImageMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: "http://i.imgur.com/zYIlgBl.png"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText
    }
  };

  callSendAPI(messageData);
}


/*
 * Send a Structured Message (Generic Message type) using the Send API.
 *
 */
function sendGenericMessage(recipientId,MessageTemplate) {
 
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: MessageTemplate
  };  

  callSendAPI(messageData);
}


/*
 * Call the Send API. The message data goes in the body. If successful, we'll 
 * get the message id in a response 
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

    } else {
      console.error("Unable to send message.");
      console.error(response);
      console.error(error);
    }
  });  
}

//assigning mission

function assignmission(id,name,picurl,Status)
{

var http = require('http');
    var Userdetails = JSON.stringify({       
        'UID': '' + id + '',
        'Name': '' + name + '',
        'URL': '' + picurl + '',
        'Status': '' + Status + ''
    });


    //5
    var extServeroptionspost = {
        host: '202.89.107.58',
        port: '80',
        path: '/FBBOT/api/InitStoreAudit',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Userdetails.length
        }
    };



    //6
    var reqPost = http.request(extServeroptionspost, function (res) {      
        res.on('data', function (data) {
            process.stdout.write(data);    
            var status=data.toString("utf8").replace('"', '').replace('"', '');
            console.log(status);                 
        });
    });


    // 7
    reqPost.write(Userdetails);
    reqPost.end();
    reqPost.on('error', function (e) {
        console.error(e);
    });
}

//send q2 status

function SendQ2status(id,Status)
{

var http = require('http');
    var QTwostatus = JSON.stringify({       
        'UID': '' + id + '',        
        'Status': '' + Status + ''
    });


    //5
    var extServeroptionspost = {
        host: '202.89.107.58',
        port: '80',
        path: '/FBBOT/api/QTwostatus',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': QTwostatus.length
        }
    };



    //6
    var reqPost = http.request(extServeroptionspost, function (res) {      
        res.on('data', function (data) {
            process.stdout.write(data);    
            var status=data.toString("utf8").replace('"', '').replace('"', '');
            console.log(status);                 
        });
    });


    // 7
    reqPost.write(QTwostatus);
    reqPost.end();
    reqPost.on('error', function (e) {
        console.error(e);
    });
}


function checkstatus(id,text,type,files)
{
console.log("enterd checkstatus/n");
var filetype="";
var url="";
if(type=="text")
{
filetype=type;
}
else
{
filetype=type;
if(type=="image"||type=="audio")
{
url=files[0].payload.url;
}
}
//SD
var http = require('http');
    var SD = JSON.stringify({       
        'uid': '' + id + '',        
        'text': '' + text + '',
         'type': '' + filetype + '',        
        'url': '' + url + ''
    });


    //5
    var extServeroptionspost = {
        host: '202.89.107.58',
        port: '80',
        path: '/FBBOT/api/findstatus',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': SD.length
        }
    };

 var reqPost = http.request(extServeroptionspost, function (res) {      
        res.on('data', function (data) {
      var status=data.toString("utf8").replace('"', '').replace('"', ''); 
      console.log("mission status = "+status);
      if(status=="New" || status=="Q1")
      {
        var messageData = {
        "attachment": {
            "type": "template",
            "payload": {
                "template_type": "generic",
                "elements": [{
                    "title": "Have you purchased any Soft drinks today?",
                    "subtitle": "",
                    "buttons": [{
                        "type": "postback",
                        "title": "Yes",
                        "payload": "Q1YES"
                    }, {
                        "type": "postback",
                        "title": "No",
                        "payload": "Q1NO"
                    }]
                }]
            }
        }
    };
      sendGenericMessage(id,messageData);  
      }
      else if(status=="Q2"){

       var messageData = {
        "attachment": {
            "type": "template",
            "payload": {
                "template_type": "generic",
                "elements": [{
                    "title": "Do you have invoices for soft drinks purchased today?",
                    "subtitle": "",
                    "buttons": [{
                        "type": "postback",
                        "title": "Yes",
                        "payload": "Q2YES"
                    }, {
                        "type": "postback",
                        "title": "No",
                        "payload": "Q2NO"
                    }]
                }]
            }
        }
    };
      sendGenericMessage(id,messageData);  

      }
       else if(status=="Q3Image"){
       sendTextMessage(id,"Please use the camera button below to take a photo of the invoice and send it to me.");
       }
       else if(status=="Q5Answer"){
       sendTextMessage(id,"How many unique soft drink items you purchased today for which you do not have the invoice?");
  sendTextMessage(id,"Please provide the number of unique items (SKU) you purchased today having different Brand/Pack size/Pack type? (Example: 2 Items purchased - if you purchased Coke 200 ML Plastic and Coke 100 ML Glass)");
       }
        else if(status=="Q4"){

         var messageData = {
        "attachment": {
            "type": "template",
            "payload": {
                "template_type": "generic",
                "elements": [{
                    "title": "Did you purchase any soft drinks today for which you do not have the invoice?",
                    "subtitle": "",
                    "buttons": [{
                        "type": "postback",
                        "title": "Yes",
                        "payload": "Q4YES"
                    }, {
                        "type": "postback",
                        "title": "No",
                        "payload": "Q4NO"
                    }]
                }]
            }
        }
    };
      sendGenericMessage(id,messageData);  

        }
         else if(status=="RepeatQ5Data"){

          var messageData = {
        "attachment": {
            "type": "template",
            "payload": {
                "template_type": "generic",
                "elements": [{
                    "title": "Do you have more items?",
                    "subtitle": "",
                    "buttons": [{
                        "type": "postback",
                        "title": "Yes",
                        "payload": "MOREITEMSYES"
                    }, {
                        "type": "postback",
                        "title": "No",
                        "payload": "MOREITEMSNO"
                    }]
                }]
            }
        }
    };
      sendGenericMessage(id,messageData);  

       //  sendTextMessage(id,"Please type in the SKU of the i th item, or take a picture of the SKU, or send me a voice recording of the SKU");  
         }
         else if(status=="Completed"){
          sendTextMessage(id,"Thank you! your mission has completed please try again tomorrow.");         
         }
         else if(status.indexOf("We have only seen information")>-1)
         {

         var messageData = {
        "attachment": {
            "type": "template",
            "payload": {
                "template_type": "generic",
                "elements": [{
                    "title": ""+status+"",
                    "subtitle": "",
                    "buttons": [{
                        "type": "postback",
                        "title": "Yes",
                        "payload": "FINALCONFIRMYES"
                    }, {
                        "type": "postback",
                        "title": "No",
                        "payload": "FINALCONFIRMNO"
                    }]
                }]
            }
        }
    };
      sendGenericMessage(id,messageData);  

         }
         else{
          sendTextMessage(id,status);   
         }

       
  });
});

  // 7
    reqPost.write(SD);
    reqPost.end();
    reqPost.on('error', function (e) {
        console.error(e);
    });


}


// Start server
// Webhooks must be available via SSL with a certificate signed by a valid 
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;

