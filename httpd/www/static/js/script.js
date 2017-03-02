// http://visjs.org/examples/network/data/dynamicData.html
window.onload = function() {
var container = document.getElementById('mynetwork');

var nodes = null;
var edges = null;
var network = null;

nodes = new vis.DataSet();
nodes.add([
{id: 1,  value: 3,  label: 'R1' , shadow:true},
{id: 2,  value: 2, label: 'R1T1', shadow:true},
{id: 3,  value: 2, label: 'R1T2', shadow:true},

{id: 4,  value: 3,  label: 'R2' , shadow:true},
{id: 5,  value: 2, label: 'R1T1', shadow:true},
{id: 6,  value: 2, label: 'R1T2', shadow:true},

{id: 7,  value: 3,  label: 'R2' , shadow:true},
{id: 8,  value: 2, label: 'R1T1', shadow:true},
{id: 9,  value: 2, label: 'R1T2', shadow:true}

]);


edges = new vis.DataSet();
edges.add([
{from: 1, to: 2, value: 6, title: '<b>link1</b>ff', shadow:true, color: "#ff0000"},
{from: 1, to: 3, value: 6, title: 'link1', shadow:true, color: "#ff0000"},

{from: 4, to: 5, value: 6, title: 'link1', shadow:true, color: "#ff0000"},
{from: 4, to: 6, value: 6, title: 'link1', shadow:true, color: "#ff0000"},

{from: 7, to: 8, value: 6, title: 'link1', shadow:true, color: "#ff0000"},
{from: 7, to: 9, value: 6, title: 'link1', shadow:true, color: "#ff0000"},

{from: 2, to: 5, value: 4, title: 'link2', shadow:true},
{from: 3, to: 6, value: 5, title: 'link2', shadow:true},

{from: 5, to: 8, value: 4, title: 'link2', shadow:true},
{from: 6, to: 9, value: 5, title: 'link2', shadow:true},

{from: 2, to: 8, value: 4, title: 'link2', shadow:true},
{from: 3, to: 9, value: 5, title: 'link2', shadow:true}
]);


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
}
};

network = new vis.Network(container, data, options);

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function addNode() {
		try {
				nodes.add({
						id: getRandomInt(10, 200),
						label: getRandomInt(10, 200)
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

function addEdge() {
		try {
				edges.add({
						id: document.getElementById('edge-id').value,
						from: document.getElementById('edge-from').value,
						to: document.getElementById('edge-to').value
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

function timeout() {
    setTimeout(function () {
				addNode();
        timeout();
    }, 1000);
}

timeout();


};
