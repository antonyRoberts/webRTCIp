import { Injectable } from '@angular/core';
import { Http, Headers } from '@angular/http';

import { Subject } from 'rxjs/Subject';
import { BehaviorSubject} from 'rxjs/BehaviorSubject';

import {JwtHelper} from 'angular2-jwt';
import {User} from '../models/user.model';
import { uuid } from '../scripts/uuid';
var uaParser = require('ua-parser-js');

declare var iframe: any;

// window is refering to the gerneral window object.
declare var window:{
    innerHeight:number,
    innerWidth: number,
    screen:{
        availWidth: any,
        availHeight: any
    },
    RTCPeerConnection: any,
    mozRTCPeerConnection: any,
    webkitRTCPeerConnection:any,
};

interface IpAddressInfo{
    ip_addr: string,
    cand_type: string,
    ip_vers: string,
    existential: string,
    userId: string,
    sessionId: string,
    sessionCreated: number,
    sessionExpires: number,
    maxWidth: number,
    maxHeight: number,
    browserWidth: number,
    browserHeight: number,
    browserName: string,
    browserMajorVers: string,
    browserDetailVers: string,
    browserEngine: string,
    browserEngineVers: string,
    cpuArchitecture: string,
    device: string,
    deviceType: string,
    deviceVendor: string,
    osName: string,
    osVers: string    
}

const HEADER = {
  headers: new Headers({
    'Content-Type': 'application/json'
  })
};

@Injectable()
export class WebRTCIpService {
    //port of webSocket Server
    private port = 9000;
    private baseIp = 'localhost:' 
    private baseUrl = this.baseIp + this.port ;  
    private currentUser: User;
    public authError: Subject<string> = new BehaviorSubject<string>(null);

    constructor(
        private http: Http, 
        private jwtHelper: JwtHelper) { }

    getCurrentUser(): User {
         //Check to see if currentUser is null.     
         if (this.currentUser == null) {
             //get the json web token form local storage.
            let jwt = localStorage.getItem('jwt');
            //If the webtoken exists decode it, and set currentUser to signed in user   
            if (jwt) {
                this.currentUser = new User(this.jwtHelper.decodeToken(jwt));
                return this.currentUser;
            }// If there is no jwt then userId is null.---> create a temporary uuid
             else
                this.authError.next('no user signed in.');
                this.currentUser = { 
                        id: uuid(),
                        username: 'Guest',
                        avatar: 'avatar'};
            }

            return this.currentUser;
    }

    getIPs(){
        let _http = this.http
        let _baseUrl = this.baseUrl;
        let _currentUser = this.getCurrentUser();
        let _browersDetails = uaParser();
        //TODO We should look at localStorage to see if we need to update based on the sessionExpiration.
        let sessionId = uuid();        
        console.log('currentUser',_currentUser);
        var ips = [];
        var ipDetalis = [];
        var ip_dups = {};

        //compatibility for firefox and chrome
        var RTCPeerConnection = window.RTCPeerConnection
            || window.mozRTCPeerConnection
            || window.webkitRTCPeerConnection;
        var useWebKit = !!window.webkitRTCPeerConnection;

        //bypass naive webrtc blocking using an iframe
        if(!RTCPeerConnection){
            //NOTE:A dummy iframe may be needed if webRTC is being blocked.
            //<iframe id="iframe" sandbox="allow-same-origin" style="display: none"></iframe>
            var win = iframe.contentWindow;
            RTCPeerConnection = win.RTCPeerConnection
                || win.mozRTCPeerConnection
                || win.webkitRTCPeerConnection;
            useWebKit = !!win.webkitRTCPeerConnection;
        }

        //minimal requirements for data connection
        var mediaConstraints = {
            optional: [{RtpDataChannels: true}]
        };
        
        // Create a stun server to tease client connection info.
        var servers = {iceServers: [{urls: "stun:stun.services.mozilla.com"}]};

        //construct a new RTCPeerConnection
        var pc = new RTCPeerConnection(servers, mediaConstraints);

        function handleCandidate(candidate){
            let candidateType = '';
            let ipVersion = '';
            let existential = '';

            //Pull the IP address from the candidate
            const ip_regex = /([0-9]{1,3}(\.[0-9]{1,3}){3}|(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])))($|\s)/;       
            const ip_addr = ip_regex.exec(candidate)[1];

            //Check for the type of ICECandidate, host, srflx, or relay
                if(candidate.includes('typ srflx')){
                    candidateType = 'srflx'
                    existential = 'external';
                }else if (candidate.includes('typ host')){
                    candidateType = 'host'
                    existential = 'internal';
                }else if (candidate.includes('typ relay')){
                    candidateType = 'relay'
                    existential = 'turnServer';
                }

            // Check for ipVersion; if it is separated by : instead of . it is ipv6
                if(ip_addr.includes('.')){
                    ipVersion = 'ipv4'
                }else{
                    ipVersion = 'ipv6'
                }    

            //Check if ip_addr is in ips[], index of -1 means it is not in. 
            let currentUnixTime = Date.now(); 
            let ipAddressInfo: IpAddressInfo ={
                ip_addr: ip_addr,
                cand_type: candidateType,
                ip_vers: ipVersion,    
                existential: existential,
                userId: _currentUser.id,
                sessionId: sessionId,
                sessionCreated: currentUnixTime,
                sessionExpires: currentUnixTime + 86400,
                maxWidth: window.screen.availWidth,
                maxHeight: window.screen.availHeight,
                browserWidth: window.innerWidth,
                browserHeight: window.innerHeight,
                browserName: _browersDetails.browser.name,
                browserMajorVers: _browersDetails.browser.major,
                browserDetailVers: _browersDetails.browser.version,
                browserEngine: _browersDetails.engine.name,
                browserEngineVers: _browersDetails.engine.version,
                cpuArchitecture: _browersDetails.cpu.architecture,
                device: _browersDetails.device.model, // Change to see if this is a desktop
                deviceType: _browersDetails.device.type,
                deviceVendor: _browersDetails.device.vendor,
                osName: _browersDetails.os.name,
                osVers: _browersDetails.os.version   
            }
    
            if(ips.indexOf(ip_addr) === -1){
                //Push just the ip_addr to the ips[] so that we can use index of to see if it is already in.
                ips.push(ip_addr);
             
                //Push the ipDetails into the ipDetails Array, this is what we will be using with localStorage  
                ipDetalis.push(ipAddressInfo);
                          
                // webRTC provides 'srflx' the outside ipaddress last because of the way it traverses the ip address chain
                if(candidateType=='srflx'){
                    //Encode the ipDetails string to base64 
                    let encodedIpDetails = btoa(JSON.stringify(ipDetalis));
                    localStorage.setItem('connection',encodedIpDetails);
                    
                    //In theory this should be the last time we need ipInfo so we can set localStorage only once.
                    //On the server side I should do the address lookup, this will keep the client unaware.
                    /** For testing purposes* */
                        let decodeMe = localStorage.getItem('connection');
                        let decoded = atob(decodeMe);
                        let meConnect = _http.post(_baseUrl + '/findLocation', {encoded:encodedIpDetails}, HEADER)    
                        meConnect.subscribe();
                 }    

            }else
                ip_dups[ip_addr] = true;
        }

        //listen for candidate events
        pc.onicecandidate = function(ice){
            //skip non-candidate events
            if(ice.candidate){
                handleCandidate(ice.candidate.candidate);
            }
        };

        //create an empty data channel
        pc.createDataChannel("");

        //create an offer sdp
        pc.createOffer(function(result){

            //trigger the stun server request
            pc.setLocalDescription(result, function(){}, function(){});

        }, function(){});

        //wait for a while to let everything done
        setTimeout(function(){
            const lines = pc.localDescription.sdp.split('\n');
      
            lines.forEach(function(line){
                if(line.indexOf('a=candidate:') === 0){
                    handleCandidate(line);
                }
            })
            return 
        }, 100);
    }
}

   
