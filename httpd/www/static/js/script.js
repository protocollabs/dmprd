
// http://visjs.org/examples/network/data/dynamicData.html
window.onload = function() {
var container = document.getElementById('mynetwork');

var nodes = null;
var edges = null;
var network = null;

nodes = new vis.DataSet();
//nodes.add([
//{id: 1, font: {size:12, color:'#FFFFFF'}, value: 6, label: 'R1' , shadow:true, shape: 'image', image: "static/images/router.png"},
//{id: 2, font: {size:12, color:'#FFFFFF'}, value: 6, label: 'R1T1', shadow:true, shape: 'image', image: "static/images/wifi-router.png"},
//{id: 3, font: {size:12, color:'#FFFFFF'}, value: 6, label: 'R1T2', shadow:true, shape: 'image', image: "static/images/wifi-router.png"},
//]);


edges = new vis.DataSet();
//edges.add([
//{from: 1, to: 2, smooth:false, value: 10, title: '<b>link1</b>ff', shadow:true, color: "#ff0000"},
//{from: 1, to: 3, smooth:false, value: 6, title: 'link1', shadow:true, color: "#ff0000" },
//]);


var container = document.getElementById('mynetwork');
var data = {
    nodes: nodes,
    edges: edges
};
var options = {
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

function addEdge(from_no, to_no, color_val, val_val) {
		try {
				edges.add({
						from: from_no,
						to: to_no,
						value: val_val,
						shadow:true,
						smooth:false,
						color: color_val
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

var base_id = 10;

function draw_platform() {
			addRouter(base_id);
			addTerminal(base_id + 1);
			addTerminal(base_id + 2);
			addTerminal(base_id + 3);

			addEdge(base_id, base_id + 1, "#444444", 6);
			addEdge(base_id, base_id + 2, "#444444", 6);
			addEdge(base_id, base_id + 3, "#444444", 6);

			//addEdge(base_id, base_id + 1);
				for (i = base_id; i >= 10; i-=10) {
				addEdge(base_id + 1, (base_id + 1) - i, "#FF0000", 6);
				addEdge(base_id + 2, (base_id + 2) - i, "#00FF00", 5);
				addEdge(base_id + 3, (base_id + 3) - i, "#00FF00", 4);
			}

		  base_id += 10;
}

function timeout() {
	setTimeout(function () {

		draw_platform();

		if (base_id < 80) {
				timeout();
		}
	}, 2000);
}

timeout();


};
