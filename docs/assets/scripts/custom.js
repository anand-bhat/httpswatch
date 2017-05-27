// Formatting function for row details
function format(row) {
	'use strict';
	return '<table><tr><td>SSL Labs report: <a target="_blank" href="https://www.ssllabs.com/ssltest/analyze.html?d=' + row[2] + '&ignoreMismatch=on">' + row[2] + '</a></td></tr></table>';
}

var gradeRank = {
	'A+': 1,
	'A': 2,
	'A-': 3,
	'B': 4,
	'C': 5,
	'D': 6,
	'E': 7,
	'T/ A+': 8,
	'T/ A': 9,
	'T/ A-': 10,
	'T/ B': 11,
	'T/ C': 12,
	'T/ D': 13,
	'T/ E': 14,
	'F': 15,
	'No HTTPS': 16,
	'Scan error': 17,
	'Could not connect': 18,
	'Not scanned': 19,
	'Unknown domain': 20
};

var gradeClass = {
	'A+': 'grade-green',
	'A': 'grade-yellowgreen',
	'A-': 'grade-lightgreen',
	'B': 'grade-orange',
	'C': 'grade-orange',
	'D': 'grade-orange',
	'E': 'grade-orange',
	'Scan error': 'grade-gray',
	'Could not connect': 'grade-gray',
	'Not scanned': 'grade-gray',
	'Unknown domain': 'grade-gray'
};

var gradesNotRequiringReport = ['A', 'A-', 'A+', 'Could not connect', 'Scan error', 'Not scanned', 'Unknown domain'];

function drawChartCountsByOrg() {
	'use strict';
	if ((typeof chartDataCountsByOrg === 'undefined') ||(typeof google === 'undefined')) {
		return;
	}

	var data = google.visualization.arrayToDataTable(chartDataCountsByOrg);

	var options = {
		bar: {groupWidth: 30},
		chartArea: {
			bottom: 50,
			top: 50
		},
		hAxis: {
			minValue: 0,
			ticks: [0, 0.25, 0.5, 0.75, 1],
			textStyle: {fontSize: 14}
		},
		height: (100 + (60 * data.getNumberOfRows())),
		isStacked: 'percent',
		legend: {
			maxLines: 1,
			position: 'top',
			textStyle: {fontSize: 14}
		},
		series: {
			0: {color: 'Green'},
			1: {color: 'YellowGreen'},
			2: {color: 'LightGreen'},
			3: {color: 'Orange'},
			4: {color: 'Orange'},
			5: {color: 'Orange'},
			6: {color: 'Orange'},
			7: {color: 'Red'},
			8: {color: 'Red'},
			9: {color: 'Red'},
			10: {color: 'Gray'},
			11: {color: 'Gray'}
		},
		tooltip: {
			textStyle: {fontSize: 14},
			showColorCode: true
		},
		vAxis: {
			textStyle: {fontSize: 14}
		}
	};

	var chart = new google.visualization.BarChart(document.getElementById('chartCountsByOrg'));
	chart.draw(data, options);
}

// Sort function for SSL Grade to show A+ first
jQuery.extend(jQuery.fn.dataTableExt.oSort, {
	'enumgrade-pre': function (a) {
		'use strict';
		return gradeRank[a] || 21;
	},

	'enumgrade-asc': function (a, b) {
		'use strict';
		return ((a < b) ? -1 : ((a > b) ? 1 : 0));
	},

	'enumgrade-desc': function (a, b) {
		'use strict';
		return ((a < b) ? 1 : ((a > b) ? -1 : 0));
	}
});

$(document).ready(function () {
	'use strict';
	var table = $('#httpsdata').DataTable({
		search: {
			search: (function () {
				if (location.hash === '') {
					return '';
				}
				var locHash = location.hash.substr(1);
				var query = locHash.substr(locHash.indexOf('q=')).split('&')[0].split('=')[1];
				if (query !== undefined){
					return decodeURIComponent(query);
				}
				return '';
			}())
		},
		columns: [
			{
				className: 'details-control',
				data: null,
				defaultContent: '',
				orderable: false
			},
			{title: 'Organization'},
			{title: 'Host'},
			{title: 'IP Address'},
			{title: 'SSL Labs Grade'},
			{title: 'Test Date', className: 'center'},
			{title: 'Status Message'},
			{title: 'Industry'},
			{title: 'Host Purpose'},
			{title: 'HTTPS Behavior'},
			{title: 'Issue Report', className: 'center', orderable: false},
			{title: '[F] Vulnerable to Heartbleed'},
			{title: '[F] Vulnerable to CVE-2014-0224'},
			{title: '[F] Vulnerable to CVE-2016-2107'},
			{title: '[F] Vulnerable to FREAK'},
			{title: '[F] Vulnerable to Logjam'},
			{title: '[F] Vulnerable to POODLE (TLS)'},
			{title: '[F] Vulnerable to DROWN'},
			{title: '[F] Vulnerable to Ticketbleed'},
			{title: '[F] Supports SSLv2'},
			{title: '[F] Supports Anonymous suites'},
			{title: '[F] Only supports RC4 suites'},
			{title: '[F] Supports Insecure renegotiation'},
			{title: '[F] No support for TLS'},
			{title: '[F] Supports insecure cipher suites'},
			{title: '[T] Untrusted certificate'},
			{title: '[C] Vulnerable to POODLE (SSLv3)'},
			{title: '[C] Lacks support for TLSv1.2'},
			{title: '[C] Uses RC4 with modern protocols'},
			{title: '[C] Uses 3DES with modern protocols'},
			{title: '[B] Supports RC4'},
			{title: '[B] Supports SSLv3'},
			{title: '[B] Uses weak DH'},
			{title: '[B] Has incomplete chain'},
			{title: '[B] Has weak private key'},
			{title: '[A-] Lacks Forward Secrecy'},
			{title: '[A-] Lacks Secure Renegotiation'}
		],
		columnDefs: [
			{
				// Show link to SSL Labs scan. Link to site rather than endpoint to see messages about inconsistent endpoints
				render: function (data, type, row, meta) {
					if (type !== 'display') {
						return data;
					}
					return '<div class="grade ' + (gradeClass[data] || 'grade-red') + '"><a target="_blank" class="white" href="https://www.ssllabs.com/ssltest/analyze.html?d=' + row[2] + '&ignoreMismatch=on">' + data + '</a></div>';
				},
				targets: 4
			},
			{
				// Show link to Github issue report
				render: function (data, type, row, meta) {
					if (type !== 'display') {
						return data;
					}

					if (data !== '' && data !== '-') {
						return '<a target="_blank" href="' + data + '">View</a>';
					}

					if ($.inArray(row[4], gradesNotRequiringReport) !== -1) {
						return data;
					}
					return '<a target="_blank" href="https://github.com/anand-bhat/httpswatch/issues/new">Create</a>';
				},
				targets: 10
			},
			{
				// For issues, show 'No' in green, 'Yes' in red highlight
				render: function (data, type, row, meta) {
					if (type !== 'display') {
						return data;
					}
					var cellClass;
					switch (data) {
					case 'Yes':
						cellClass = 'center badhighlight';
						break;
					case 'No':
						cellClass = 'center good';
						break;
					default:
						cellClass = 'center';
					}
					return '<div class="' + cellClass + '">' + data + '</div>';
				},
				targets: [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36]
			},
			{
				// Add title to cells
				createdCell: function (cell, cellData, rowData, rowIndex, colIndex) {
					$(cell).prop('title', 'Organization: ' + rowData[1] + '\r\nHost: ' + rowData[2] + '\r\nIP Address: ' + rowData[3] + '\r\nSSL Labs Grade: ' + rowData[4]);
				},
				targets: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36]
			},
			{type: 'enumgrade', targets: 4},
			{visible: false, targets: [0, 5, 6, 7, 8, 9, 10]}
		],
		data: dataSet,
		deferRender: true,
		fixedHeader: { footer: true, header: true },
		initComplete: function () {
			// Add filters
			this.api().columns().every(function () {
				var column = this;

				if (column.index() === 0 || column.index() === 10) {
					// Do not add filters to 0th and 10th column (expander and report link)
					$(column.footer()).empty();
					return;
				}

				var select = $('<select><option value="">No Choice</option></select>')
					.appendTo($(column.footer()).empty())
					.on('change', function () {
						var val = $.fn.dataTable.util.escapeRegex($(this).val());

						if (val === '') {
							val = '.*.';
						}

						column.search(val ? '^' + val + '$' : '-', true, false).draw();
					});

				column.data().unique().sort().each(function (d, j) {
					select.append('<option value="' + d + '">' + d + '</option>');
				});
			});

			// Hide columns that do not have a 'Yes'.
			this.api().columns().every(function () {
				var column = this;
				var columnIndex = column.index();
				if (columnIndex < 11) {
					// Columns whose default visibility is controlled by table properties
					return;
				}
				var showColumn = column.data().filter(function(value, index) {return value === 'Yes';}).any();
				if (!showColumn) {
					$('a.toggle-column[data-column=' + columnIndex + ']').css('text-decoration', 'line-through');
					column.visible(false);
				}
			});
		},
		lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, 'All']],
		order: [[1, 'asc'], [2, 'asc'], [3, 'asc']]
	});

	// Expand/ collapse details section
	$('#httpsdata tbody').on('click', 'td.details-control', function () {
		var tr = $(this).closest('tr');
		var row = table.row(tr);

		if (row.child.isShown()) {
			// Close this row
			row.child.hide();
			tr.removeClass('shown');
		} else {
			// Open this row
			row.child(format(row.data())).show();
			tr.addClass('shown');
		}
	});

	// Toggle column visibility and option state
	$('a.toggle-column').on('click', function (e) {
		e.preventDefault();
		var column = table.column($(this).attr('data-column'));
		if (column.visible()) {
			$(this).css('text-decoration', 'line-through');
			//$(this).toggleClass('strikethrough'); //Delayed repaint
			column.visible(false);
		} else {
			$(this).css('text-decoration', 'none');
			//$(this).toggleClass('strikethrough'); //Delayed repaint
			column.visible(true);
		}
		table.fixedHeader.adjust();
	});

	// Toggle options section visibility
	$('#toggleColumns').on('click', function (e) {
		e.preventDefault();
		if ($('#toggleColumnsSection').is(':visible')) {
			$('#toggleColumnsSection').hide();
			$(this).text('[show section]');
		}
		else {
			$('#toggleColumnsSection').show();
			$(this).text('[hide section]');
		}
	});

	// Toggle chart section visibility
	$('#toggleChartCountsByOrg').on('click', function (e) {
		e.preventDefault();
		if ($('#chartCountsByOrg').is(':visible')) {
			$('#chartCountsByOrg').hide();
			$(this).text('[show section]');
		}
		else {
			$('#chartCountsByOrg').show();
			$(this).text('[hide section]');
		}
	});

	// If the datatable with HTTPS data is searched, sync it to the URL hash
	$('#httpsdata').on('search.dt', function(e, settings) {
		e.preventDefault();
		var query = $("input[type=search]").val();
		if (query) {
			location.hash = 'q=' + encodeURIComponent(query);
		} else {
			location.hash = '';
		}
	});

	if (typeof google === 'undefined') {
		return;
	}
	google.charts.load('current', {packages: ['corechart']});
	google.charts.setOnLoadCallback(drawChartCountsByOrg);
});