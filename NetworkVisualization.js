// NetworkVisualization.js

class NetworkVisualization {
    constructor(elementId) {
        this.element = document.getElementById(elementId);
        this.svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        this.svg.setAttribute("width", "300");
        this.svg.setAttribute("height", "300");
        this.svg.classList.add("border", "rounded");
        this.element.appendChild(this.svg);
    }

    updateNetwork(users) {
        // Clear previous network
        while (this.svg.firstChild) {
            this.svg.removeChild(this.svg.firstChild);
        }

        // Calculate positions for nodes
        const nodes = users.map((user, index) => ({
            id: user.id,
            name: user.username,
            x: 150 + 100 * Math.cos(2 * Math.PI * index / users.length),
            y: 150 + 100 * Math.sin(2 * Math.PI * index / users.length),
        }));

        // Create links between nodes
        const links = [];
        for (let i = 0; i < nodes.length; i++) {
            for (let j = i + 1; j < nodes.length; j++) {
                links.push({
                    source: nodes[i],
                    target: nodes[j],
                });
            }
        }

        // Draw links
        links.forEach(link => {
            const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
            line.setAttribute("x1", link.source.x);
            line.setAttribute("y1", link.source.y);
            line.setAttribute("x2", link.target.x);
            line.setAttribute("y2", link.target.y);
            line.setAttribute("stroke", "#999");
            line.setAttribute("stroke-width", "1");
            this.svg.appendChild(line);
        });

        // Draw nodes
        nodes.forEach(node => {
            const group = document.createElementNS("http://www.w3.org/2000/svg", "g");

            const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
            circle.setAttribute("cx", node.x);
            circle.setAttribute("cy", node.y);
            circle.setAttribute("r", "5");
            circle.setAttribute("fill", "#69b3a2");

            const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
            text.setAttribute("x", node.x);
            text.setAttribute("y", node.y + 15);
            text.setAttribute("text-anchor", "middle");
            text.setAttribute("font-size", "10");
            text.textContent = node.name;

            group.appendChild(circle);
            group.appendChild(text);
            this.svg.appendChild(group);
        });
    }
}