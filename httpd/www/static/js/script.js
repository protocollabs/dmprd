// http://visjs.org/examples/network/data/dynamicData.html
window.onload = function() {
var container = document.getElementById('mynetwork');

var nodes = null;
var edges = null;
var network = null;

nodes = new vis.DataSet();
nodes.add([
{id: 1, font: {size:12, color:'#FFFFFF'}, value: 6, label: 'R1' , shadow:true, shape: 'image', image: "static/images/router.png"},
{id: 2, font: {size:12, color:'#FFFFFF'}, value: 6, label: 'R1T1', shadow:true, shape: 'image', image: "static/images/wifi-router.png"},
{id: 3, font: {size:12, color:'#FFFFFF'}, value: 6, label: 'R1T2', shadow:true, shape: 'image', image: "static/images/wifi-router.png"},

{id: 4, font: {size:12, color:'#FFFFFF'}, value: 6, label: 'R2' , shadow:true, shape: 'image', image: "static/images/router.png"},
{id: 5, font: {size:12, color:'#FFFFFF'}, value: 6, label: 'R1T1', shadow:true, shape: 'image', image: "static/images/wifi-router.png"},
{id: 6, font: {size:12, color:'#FFFFFF'}, value: 6, label: 'R1T2', shadow:true, shape: 'image', image: "static/images/wifi-router.png"},

{id: 7, font: {size:12, color:'#FFFFFF'}, value: 6, label: 'R2' , shadow:true, shape: 'image', image: "static/images/router.png"},
{id: 8, font: {size:12, color:'#FFFFFF'}, value: 6, label: 'R1T1', shadow:true, shape: 'image', image: "static/images/wifi-router.png"},
{id: 9, font: {size:12, color:'#FFFFFF'}, value: 6, label: 'R1T2', shadow:true, shape: 'image', image: "static/images/wifi-router.png"}

]);


edges = new vis.DataSet();
edges.add([
{from: 1, to: 2, smooth:false, value: 10, title: '<b>link1</b>ff', shadow:true, color: "#ff0000"},
{from: 1, to: 3, smooth:false, value: 6, title: 'link1', shadow:true, color: "#ff0000" },

{from: 4, to: 5, smooth:false, value: 6, title: 'link1', shadow:true, color: "#ff0000"},
{from: 4, to: 6, smooth:false, value: 6, title: 'link1', shadow:true, color: "#ff0000"},

{from: 7, to: 8, smooth:false, value: 6, title: 'link1', shadow:true, color: "#ff0000"},
{from: 7, to: 9, smooth:false, value: 6, title: 'link1', shadow:true, color: "#ff0000"},

{from: 2, to: 5, smooth:false, value: 1, title: 'link2', shadow:true, color: "#d500f9"},
{from: 3, to: 6, smooth:false, value: 5, title: 'link2', shadow:true, color: "#d500f9"},

{from: 5, to: 8, smooth:false, value: 4, title: 'link2', shadow:true, color: "#d500f9"},
{from: 6, to: 9, smooth:false, value: 5, title: 'link2', shadow:true, color: "#d500f9"},

{from: 2, to: 8, smooth:false, value: 4, title: 'link2', shadow:true, color: "#d500f9"},
{from: 3, to: 9, smooth:false, value: 5, title: 'link2', shadow:true, color: "#d500f9"}
]);


var container = document.getElementById('mynetwork');
var data = {
    nodes: nodes,
    edges: edges
};
var options = {
	  stabilize: true,
		nodes: {
			shape: 'dot',
			scaling:{
				label: {
					min:8,
					max:20
				}
			}
		},
	layout : {
		//hierarchical: true,
		improvedLayout : true
	}
};

network = new vis.Network(container, data, options);

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function addRouter(id_no) {
		try {
				nodes.add({
						id: id_no,
						label: id_no,
						value: 6,
						shadow: true,
						shape: 'image', image: "static/images/router.png",
						font: {size:12, color:'#FFFFFF'}
				});
		}
		catch (err) {
				alert(err);
		}
}

function addTerminal(id_no) {
		try {
				nodes.add({
						id: id_no,
						label: id_no,
						value: 6,
						shadow: true,
						shape: 'image', image: "static/images/wifi-router.png",
						font: {size:12, color:'#FFFFFF'}
				});
		}
		catch (err) {
				alert(err);
		}
}

function updateNode() {
		try {
				nodes.update({
						id: document.getElementById('node-id').value,
						label: document.getElementById('node-label').value
				});
		}
		catch (err) {
				alert(err);
		}
}

function removeNode() {
		try {
				nodes.remove({id: document.getElementById('node-id').value});
		}
		catch (err) {
				alert(err);
		}
}

function addEdge(id_no, from_no, to_no) {
		try {
				edges.add({
						id: id_no,
						from: from_no,
						to: to_no,
						value: 6,
						shadow:true,
						smooth:false,
						color: "#0000FF"
				});
		}
		catch (err) {
				alert(err);
		}
}
function updateEdge() {
		try {
				edges.update({
						id: document.getElementById('edge-id').value,
						from: document.getElementById('edge-from').value,
						to: document.getElementById('edge-to').value
				});
		}
		catch (err) {
				alert(err);
		}
}
function removeEdge() {
		try {
				edges.remove({id: document.getElementById('edge-id').value});
		}
		catch (err) {
				alert(err);
		}
}

var node_add_counter = 10;
function timeout() {
	if (node_add_counter > 40) {
		return;
	}
	setTimeout(function () {
			addRouter(node_add_counter);
			addTerminal(node_add_counter + 1);
			addEdge(node_add_counter + 2, node_add_counter, node_add_counter + 1);
			addEdge(node_add_counter + 3, node_add_counter, getRandomInt(1, 9));
			timeout();
	}, 2000);
	node_add_counter += 4;
}

timeout();


};
